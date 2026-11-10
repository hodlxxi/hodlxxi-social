import { FinalizeOutcomeUnknown } from "./ubid-social-enrollment-v2-client.mjs";
// Explicit native V2 cross-device registration. No participant-key custody.
import { randomBytes, webcrypto } from "node:crypto";
import { canonical, exact, hex64, parseClosedJson } from "../../web/social-mobile-protocol-v1.mjs";
import { createPairingQr, parsePairingQr } from "../../web/mobile-device-authorization-contract-v1.mjs";
import { acceptanceIdV2, authorizationDigestV2, parseApprovalEventV2, parseAuthorizationEnvelopeV2,
  pairingSecretCommitmentV2, verifyPairingPossessionV2 } from "../../web/mobile-device-authorization-contract-v2.mjs";
import { preEnrollmentComparisonCode } from "../../web/mobile-device-authorization-seams-v2.mjs";
import { parseCookieHeader, SESSION_COOKIE_NAME, serializeHostCookie, expireSessionCookie }
  from "./social-oauth-cookie.mjs";

import { ENROLLMENT_BROWSER_PREFIX, ENROLLMENT_CONTEXT_COOKIE, ENROLLMENT_CSRF_HEADER,
  commands, ENROLLMENT_BROWSER_POST_ROUTES } from "./social-enrollment-v2-routes.mjs";
export { ENROLLMENT_BROWSER_POST_ROUTES } from "./social-enrollment-v2-routes.mjs";
const deny = () => { throw new TypeError("device registration unavailable"); };
const json = (status, value, extra = {}) => ({ status, body: canonical(value), headers: {
  "Content-Type": "application/json", "Cache-Control": "no-store", Pragma: "no-cache", ...extra } });
const iso = (seconds) => new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
const token = () => randomBytes(32).toString("hex");

export function createEnrollmentBrowserRoutes({ publicOrigin, sessions, desktopManager, nativeManager,
  sessionClient, enrollmentClient, finalizer, authorityReader, bindingLifetimeSeconds, now = Date.now, capacity = 1024 }) {
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 10000 ||
      !Number.isSafeInteger(bindingLifetimeSeconds) || bindingLifetimeSeconds < 1 || bindingLifetimeSeconds > 31536000 ||
      typeof finalizer !== "function" || typeof authorityReader !== "function") deny();
  const contexts = new Map(), pairings = new Map();
  let previous = -1;
  const clock = () => { const at = now(); if (!Number.isSafeInteger(at) || at < 0 || at < previous) deny(); previous = at; return at; };
  const cookies = (header) => {
    if ((header?.split(";").filter((s) => s.trim().startsWith(ENROLLMENT_CONTEXT_COOKIE + "=")) ?? []).length > 1) deny();
    return parseCookieHeader(header);
  };
  const sweep = () => {
    const at = clock();
    for (const [key, c] of contexts) if (c.until <= at) contexts.delete(key);
    for (const [key, p] of pairings) if (p.expires * 1000 + 300000 <= at) pairings.delete(key);
  };
  const currentContext = (header, { denied = false } = {}) => {
    sweep(); const parsed = cookies(header), c = contexts.get(parsed.get(ENROLLMENT_CONTEXT_COOKIE));
    if (!c || !denied && c.denied) deny();
    const id = parsed.get(SESSION_COOKIE_NAME);
    if (c.role === "desktop" ? id !== c.sessionId : id !== undefined && id !== c.alias) deny();
    return c;
  };
  const current = (c) => contexts.get(c.id) === c && !c.denied && clock() < c.until;
  const fullDesktop = async (c) => {
    if (c.role !== "desktop" || !current(c)) deny();
    const record = await desktopManager.read(c.sessionId);
    if (!record || Object.hasOwn(record, "kind") || Object.hasOwn(record, "issuanceId")) deny();
    const authority = await authorityReader(record.subject);
    if (!current(c) || sessions.get(c.sessionId) !== record || authority?.subject !== record.subject ||
        authority.status !== "full" || authority.valid !== true) deny();
    return record;
  };
  const pairing = (c, id, { historical = false } = {}) => {
    if (!hex64(id) || c.pairingId !== id) deny();
    const p = pairings.get(id);
    if (!p || !historical && (p.cancelled || clock() >= p.expires * 1000) ||
        (c.role === "desktop" ? p.desktop !== c : p.phone !== c)) deny();
    return p;
  };
  const offer = (p) => Object.freeze({ pairingId: p.id, revision: p.revision, subject: p.subject,
    secretCommitment: p.secretCommitment, desktopContext: p.desktopContext,
    createdAt: iso(p.created), expiresAt: iso(p.expires), bindingLifetimeSeconds });
  const status = (p) => ({ status: p.cancelled ? "cancelled" : clock() >= p.expires * 1000 ? "expired"
    : p.approvalWire ? "approved" : p.authorizationWire ? "proposed" : "waiting", expiresAt: iso(p.expires) });
  const phone = async (c, header) => {
    if (c.role !== "phone" || !c.alias || cookies(header).get(SESSION_COOKIE_NAME) !== c.alias || !current(c)) deny();
    const p = pairings.get(c.pairingId);
    if (!p || p.cancelled || p.phone !== c) deny();
    const record = await nativeManager.capabilityRead(c.alias);
    if (!record || !current(c)) deny();
    return record;
  };
  const logout = async (c) => {
    c.denied = true;
    if (c.issuing) return json(503, { authenticated: false, logout: "pending" });
    if (c.orphan) { await nativeManager.cancelUninstalled(c.orphan); c.orphan = undefined; }
    if (c.alias) await nativeManager.logout(c.alias);
    return json(200, { authenticated: false, logout: c.alias ? "confirmed" : "local-only" }, { "Set-Cookie": expireSessionCookie() });
  };
  async function handle(request) {
    let command;
    for (const name of Object.keys(commands)) if (request.url === ENROLLMENT_BROWSER_PREFIX + "/" + name) command = name;
    // Existing entry/logout UI can use its original context header with a V2 presentation.
    const compatibility = ["/auth/logout", "/auth/mobile/v1/context"].includes(request.url);
    let existing;
    if (compatibility) { try { existing = currentContext(request.headers?.cookie, { denied: true });
      if (existing.role !== "phone") existing = undefined; } catch { return null; } }
    if (!command && !existing) {
      if (request.url === "/auth/login") {
        try { const c = currentContext(request.headers?.cookie); if (c.role === "phone" && c.pairingId) return json(409, { error: "request_rejected" }); } catch {}
      }
      return null;
    }
    if (request.method !== "POST" || request.headers?.origin !== publicOrigin ||
        request.headers?.["content-type"] !== "application/json") return json(403, { error: "request_rejected" });
    try {
      const body = parseClosedJson(request.body, { canonicalOnly: false, maximum: 65536, depth: 3 });
      if (existing && request.url === "/auth/mobile/v1/context") {
        exact(body, body.purpose === undefined ? [] : ["purpose"]);
        if (body.purpose !== undefined && !["login", "logout"].includes(body.purpose) || body.purpose === "login") deny();
        return json(200, { csrf: existing.csrf });
      }
      if (existing && request.url === "/auth/logout") {
        exact(body, []);
        if (existing.role !== "phone") return null;
        if (request.headers["x-hodlxxi-mobile-csrf"] !== existing.csrf) deny();
        return await logout(existing);
      }
      exact(body, commands[command]);
      if (command === "context") {
        if (!["desktop", "phone"].includes(body.role)) deny();
        let c; try { c = currentContext(request.headers.cookie); } catch {}
        if (c) { if (c.role !== body.role) deny(); return json(200, { csrf: c.csrf }); }
        const parsed = cookies(request.headers.cookie), sessionId = parsed.get(SESSION_COOKIE_NAME);
        // Native or legacy authenticated cookies cannot be relabeled as an anonymous phone.
        if (body.role === "phone" && sessionId || body.role === "desktop" && !sessionId || contexts.size >= capacity) deny();
        c = { id: randomBytes(32).toString("base64url"), csrf: token(), role: body.role,
          sessionId: body.role === "desktop" ? sessionId : undefined, until: clock() + 600000, denied: false };
        if (c.role === "desktop") {
          const record = await desktopManager.read(c.sessionId);
          if (!record || Object.hasOwn(record, "kind") || Object.hasOwn(record, "issuanceId")) deny();
        }
        contexts.set(c.id, c);
        return json(200, { csrf: c.csrf }, { "Set-Cookie": serializeHostCookie(ENROLLMENT_CONTEXT_COOKIE, c.id, 600) });
      }
      const c = currentContext(request.headers.cookie, { denied: command === "logout" });
      if (request.headers[ENROLLMENT_CSRF_HEADER] !== c.csrf) deny();
      if (command === "logout") return await logout(c);
      if (command === "create") return await desktopManager.serial("v2-create:" + c.id, async () => {
        const desktop = await fullDesktop(c);
        if (c.pairingId) { const p = pairing(c, c.pairingId); return json(200, { qr: p.qr, offer: offer(p) }); }
        if (pairings.size >= capacity) deny();
        const id = token(), secret = token(), created = Math.floor(clock() / 1000);
        const p = { id, revision: token(), desktop: c, desktopRecord: desktop, subject: desktop.subject,
          created, expires: created + 300, desktopContext: token(), qr: createPairingQr(id, secret),
          secretCommitment: await pairingSecretCommitmentV2(secret, webcrypto) };
        if (!current(c) || pairings.has(id)) deny();
        pairings.set(id, p); c.pairingId = id;
        return json(200, { qr: p.qr, offer: offer(p) });
      });
      if (["offer", "propose"].includes(command)) {
        if (c.role !== "phone") deny();
        const qr = parsePairingQr(body.qr), p = pairings.get(qr.pairingId);
        if (!p || p.cancelled || clock() >= p.expires * 1000 || c.pairingId && c.pairingId !== p.id ||
            p.phone && p.phone !== c || await pairingSecretCommitmentV2(qr.secret, webcrypto) !== p.secretCommitment) deny();
        if (command === "offer") return json(200, offer(p));
        return await desktopManager.serial("v2:" + p.id, async () => {
          if (!current(c) || p.phone && p.phone !== c) deny();
          const envelope = await verifyPairingPossessionV2(body.authorizationWire, { subject: p.subject,
            secret: qr.secret, possessionProof: body.possessionProof, nowMs: clock(), cryptoImpl: webcrypto, proposal: undefined });
          for (const name of ["pairingId", "secretCommitment", "desktopContext"])
            if (envelope.context[name] !== offer(p)[name]) deny();
          if (envelope.context.createdAt !== p.created || envelope.context.expiresAt !== p.expires ||
              p.authorizationWire && p.authorizationWire !== body.authorizationWire) deny();
          const desktop = await fullDesktop(p.desktop);
          if (desktop !== p.desktopRecord) deny();
          // Retain original ownership before awaiting the native commit.
          p.phone = c; c.pairingId = p.id; p.authorizationWire = body.authorizationWire;
          await sessionClient.offer({ body: { authorizationWire: p.authorizationWire }, viewerAccessToken: desktop.viewerAccessToken });
          if (!current(c) || p.cancelled || clock() >= p.expires * 1000) deny();
          p.nativeOfferConfirmed = true;
          p.digest = await authorizationDigestV2(p.authorizationWire, { subject: p.subject, cryptoImpl: webcrypto });
          return json(200, { ...status(p), comparisonCode: preEnrollmentComparisonCode(p.digest) });
        });
      }
      if (["inspect", "approve", "cancel", "status", "issue", "recover"].includes(command)) {
        const p = pairing(c, body.pairingId, { historical: ["status", "cancel", "recover"].includes(command) });
        if (command === "status") return json(200, status(p));
        if (command === "inspect") {
          await fullDesktop(c);
          return json(200, { ...status(p), authorizationWire: p.nativeOfferConfirmed ? p.authorizationWire : null,
            revision: p.revision, comparisonCode: p.digest ? preEnrollmentComparisonCode(p.digest) : null });
        }
        if (command === "cancel") {
          if (c.role !== "desktop") deny();
          await fullDesktop(c); p.cancelled = true;
          if (p.phone) {
            p.phone.denied = true;
            if (p.phone.issuing) return json(503, { error: "cancellation_pending" });
            if (p.phone.orphan) { await nativeManager.cancelUninstalled(p.phone.orphan); p.phone.orphan = undefined; }
            if (p.phone.alias) await nativeManager.logout(p.phone.alias);
          }
          return json(200, { status: "cancelled" });
        }
        return await desktopManager.serial("v2:" + p.id, async () => {
          if (!current(c) || p.cancelled || !p.nativeOfferConfirmed) deny();
          if (command === "approve") {
            await fullDesktop(c);
            if (body.comparisonCode !== preEnrollmentComparisonCode(p.digest)) deny();
            const approval = await parseApprovalEventV2(body.approvalWire, { subject: p.subject, cryptoImpl: webcrypto });
            if (approval.envelope.wire !== p.authorizationWire || p.approvalWire && p.approvalWire !== body.approvalWire) deny();
            p.approvalWire = body.approvalWire;
            p.acceptanceId = await acceptanceIdV2(p.approvalWire, { subject: p.subject, cryptoImpl: webcrypto });
            return json(200, { ...status(p), acceptanceId: p.acceptanceId });
          }
          if (c.role !== "phone" || !p.approvalWire) deny();
          const desktop = await fullDesktop(p.desktop);
          if (desktop !== p.desktopRecord) deny();
          const proofs = { operationId: p.id, approvalWire: p.approvalWire,
            secret: body.secret, possessionProof: body.possessionProof, verifier: body.verifier, deliveryKey: body.deliveryKey };
          if (p.delivery && p.delivery !== canonical(proofs)) deny();
          p.delivery = canonical(proofs); c.issuing = true;
          try {
            const issued = await sessionClient[command]({ body: proofs,
              ...(command === "issue" ? { viewerAccessToken: desktop.viewerAccessToken } : {}) });
            if (!issued.currentActive) deny();
            c.orphan = issued;
            if (!current(c) || p.cancelled) { await nativeManager.cancelUninstalled(issued); c.orphan = undefined; deny(); }
            const presented = await nativeManager.install(issued, { subject: p.subject, acceptanceId: p.acceptanceId,
              maximumExpiresAt: p.expires * 1000, stillCurrent: () => current(c) && !p.cancelled });
            c.alias = presented.id; c.orphan = undefined;
            return json(200, { authenticated: true, subject: presented.subject, receipt: presented.receipt, messaging: "not-ready" },
              { "Set-Cookie": serializeHostCookie(SESSION_COOKIE_NAME, presented.id, presented.maxAge) });
          } finally { c.issuing = false; }
        });
      }
      const credential = await phone(c, request.headers.cookie);
      return await desktopManager.serial("v2-context:" + c.id, async () => {
        if (!current(c)) deny();
        if (command === "challenge") {
          const value = await enrollmentClient.challenge({ body: { issuanceId: credential.issuanceId },
            viewerAccessToken: credential.viewerAccessToken });
          if (!current(c)) deny();
          if (c.challenge && canonical(c.challenge) !== canonical(value)) deny();
          c.challenge = value;
          return json(200, value);
        }
        if (command !== "complete" || !c.challenge) deny();
        c.finalization ??= {};
        let result;
        try { result = await finalizer(c.finalization, { phone: credential, challenge: c.challenge, phoneProofWire: body.phoneProofWire }); }
        catch (error) {
          if (error instanceof FinalizeOutcomeUnknown) return json(200, { outcome: "unknown", messaging: "not-ready", finalAdmission: "denied" });
          throw error;
        }
        if (!current(c)) deny();
        return json(200, { registered: true, receiptWire: result.receiptWire, historicalRecovery: result.historicalRecovery,
          messaging: "not-ready", finalAdmission: "denied" });
      });
    } catch { return json(503, { error: "device_registration_unavailable" }); }
  }
  return Object.freeze({ handle, postRoutes: ENROLLMENT_BROWSER_POST_ROUTES });
}
