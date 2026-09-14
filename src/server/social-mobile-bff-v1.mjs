import { closedServerValue } from "./ubid-social-mobile-client-v1.mjs";
import { randomBytes, createHash } from "node:crypto";
import { canonicalHttpsOrigin } from "./social-oauth-config.mjs";
import { parseCookieHeader, SESSION_COOKIE_NAME, serializeHostCookie, expireSessionCookie } from "./social-oauth-cookie.mjs";
import { isMobileSession } from "./social-mobile-session-v1.mjs";
import { canonical, exact, parseClosedJson, MOBILE_COMMANDS, ISSUANCE_COMMANDS, SOCIAL_MOBILE_PREFIX,
  MOBILE_CSRF_HEADER, validateCommand, validateMobileResponse, inspectPhoneSource, milliseconds, unavailable } from "../../web/social-mobile-protocol-v1.mjs";
import { parsePhoneSessionExchangeIdentity, phoneExchangeCommitment, verifyPairingScan, parsePairingQr } from "../../web/mobile-device-authorization-contract-v1.mjs";

export const MOBILE_COOKIE = "__Host-hodlxxi-social-mobile";
const routes = Object.fromEntries(Object.entries(MOBILE_COMMANDS).filter(([name]) => name !== "oauthInvalidate")
  .map(([name, spec]) => [SOCIAL_MOBILE_PREFIX + "/" + spec.path, { name, spec }]));
for (const name of ["issue", "recover"]) routes[SOCIAL_MOBILE_PREFIX + "/session/" + name] = { name, spec: ISSUANCE_COMMANDS[name], issuance: true };
export const MOBILE_POST_ROUTES = Object.freeze([SOCIAL_MOBILE_PREFIX + "/context", ...Object.keys(routes), "/auth/logout"]);
const json = (status, value, headers = {}) => ({ status, body: canonical(value), headers: {
  "Content-Type": "application/json", "Cache-Control": "no-store", Pragma: "no-cache", ...headers } });
const publicError = () => json(503, { error: "mobile_authorization_unavailable" });
const fingerprint = (s) => createHash("sha256").update(s, "ascii").digest("hex");

export function createMobileBffRoutes({ publicOrigin, manager, mobileClient, issuanceClient, now = Date.now, random = randomBytes, capacity = 1024 }) {
  canonicalHttpsOrigin(publicOrigin);
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 10000) unavailable();
  const contexts = new Map();
  const cookies = (header) => {
    // The older cookie parser only cardinality-checks its two original names.
    if ((header?.split(";").filter((s) => s.trim().startsWith(MOBILE_COOKIE + "=")) ?? []).length > 1) unavailable();
    return parseCookieHeader(header);
  };
  const sweep = () => { for (const [k, v] of contexts) if (v.until <= now()) contexts.delete(k); };
  function context(header, allowDenied = false) {
    sweep(); const c = cookies(header), id = c.get(MOBILE_COOKIE), value = contexts.get(id), sessionId = c.get(SESSION_COOKIE_NAME);
    if (!value || !allowDenied && value.denied ||
        sessionId !== value.sessionId && sessionId !== value.alias ||
        value.sessionId === undefined && sessionId !== undefined && sessionId !== value.alias) unavailable();
    return { id, value, sessionId };
  }
  const oauthGuard = Object.freeze({
    begin(header) { const c = context(header); if (c.sessionId || c.value.phone || c.value.oauthStarted) unavailable(); c.value.oauthStarted = true; return c; },
    valid(fence, header) {
      try { const c = context(header); return c.value === fence.value && !c.sessionId && !c.value.phone && !c.value.denied; } catch { return false; }
    }
  });
  async function bindPhone(c, body) {
    const parsed = await inspectPhoneSource(body.source, manager.cryptoImpl);
    await verifyPairingScan(body.source, { qr: body.qr, possessionProof: body.possessionProof,
      subject: parsed.semantic.subject, now: parsed.semantic.issuedAt, cryptoImpl: manager.cryptoImpl });
    if (parsed.semantic.action === "revoke" || c.phone && c.phone.source !== body.source) unavailable();
    if (c.offer) {
      for (const k of ["pairingId", "secretCommitment", "desktopContext", "createdAt", "expiresAt"])
        if (parsed.context[k] !== c.offer[k]) unavailable();
      if (parsed.semantic.subject !== c.offer.subject) unavailable();
    }
    if (!c.phone) c.phone = { source: body.source, parsed, qrSecretHash: fingerprint(parsePairingQr(body.qr).secret) };
    c.until = Math.min(c.until, milliseconds(parsed.context.expiresAt) + 300000);
    return parsed;
  }
  async function proofs(c, body) {
    const p = c.phone;
    if (!p || p.parsed.context.pairingId !== body.pairingId || p.parsed.digest !== body.authorizationDigest ||
        p.revision !== body.revision || await phoneExchangeCommitment(body.verifier, manager.cryptoImpl) !== p.parsed.context.exchangeCommitment) unavailable();
    if (body.deliveryKey) {
      if ([body.verifier, p.parsed.semantic.subject, p.parsed.semantic.binding.publicKey, p.parsed.semantic.binding.deviceId, p.parsed.semantic.requestId].includes(body.deliveryKey) ||
          fingerprint(body.deliveryKey) === p.qrSecretHash) unavailable();
      const hash = fingerprint(body.deliveryKey);
      if (p.delivery && p.delivery !== hash) unavailable();
      p.delivery = hash;
    }
    return p;
  }
  async function exchange(c, body) {
    const p = await proofs(c, body);
    const handoff = validateMobileResponse("phoneExchange", closedServerValue(await mobileClient.phoneExchange({ body })));
    if (handoff.revision !== p.revision || handoff.operation !== p.parsed.semantic.action) unavailable();
    await parsePhoneSessionExchangeIdentity(canonical(handoff.identity), { authorization: p.source, verifier: body.verifier,
      subject: p.parsed.semantic.subject, now: p.parsed.semantic.issuedAt, cryptoImpl: manager.cryptoImpl });
    return handoff;
  }
  async function handle(request) {
    const path = request.url;
    if (!MOBILE_POST_ROUTES.includes(path)) return null;
    if (request.method !== "POST" || request.headers?.origin !== publicOrigin || request.headers?.["content-type"] !== "application/json") return json(403, { error: "request_rejected" });
    try {
      const body = parseClosedJson(request.body, { canonicalOnly: false, depth: 2 });
      if (path === SOCIAL_MOBILE_PREFIX + "/context") {
        exact(body, []); sweep();
        let existing;
        try { existing = context(request.headers.cookie); } catch {}
        if (existing) return json(200, { csrf: existing.value.csrf });
        const previousId = cookies(request.headers.cookie).get(SESSION_COOKIE_NAME);
        const sessionId = previousId && manager.retained(previousId) ? previousId : undefined;
        if (contexts.size >= capacity) unavailable();
        const id = random(32).toString("base64url"), csrf = random(32).toString("hex");
        contexts.set(id, { csrf, sessionId, until: now() + 600000, denied: false });
        const transactionCookie = serializeHostCookie(MOBILE_COOKIE, id, 600);
        return json(200, { csrf }, { "Set-Cookie": previousId && !sessionId ? [expireSessionCookie(), transactionCookie] : transactionCookie });
      }
      const ctx = context(request.headers.cookie, path === "/auth/logout"), c = ctx.value;
      if (request.headers[MOBILE_CSRF_HEADER] !== c.csrf) unavailable();
      if (path === "/auth/logout") {
        exact(body, []); c.denied = true;
        if (!c.logoutId) c.logoutId = ctx.sessionId ?? c.alias;
        if (c.issuing) return json(503, { authenticated: false, logout: "pending" });
        if (c.orphan) {
          try { await manager.cancelUninstalled(c.orphan); c.orphan = undefined; c.orphanCancelled = true; }
          catch { return json(503, { authenticated: false, logout: "pending" }); }
        }
        if (c.orphanCancelled && !c.logoutId) return json(200, { authenticated: false, logout: "confirmed" }, { "Set-Cookie": expireSessionCookie() });
        if (!c.logoutId) return json(200, { authenticated: false, logout: "local-only" }, { "Set-Cookie": expireSessionCookie() });
        try {
          await manager.logout(c.logoutId);
          return json(200, { authenticated: false, logout: "confirmed" }, { "Set-Cookie": expireSessionCookie() });
        } catch { return json(503, { authenticated: false, logout: "pending" }); }
      }
      const { name, spec, issuance } = routes[path];
      const input = validateCommand(spec, body);
      return await manager.serial(`context:${ctx.id}`, async () => {
        const stillCurrent = () => contexts.get(ctx.id) === c && !c.denied && c.until > now();
        if (!stillCurrent()) unavailable();
        let result;
        if (spec.group === "desktop") {
          const s = ctx.sessionId ? await manager.read(ctx.sessionId) : null;
          if (!s || isMobileSession(s)) unavailable();
          result = validateMobileResponse(name, closedServerValue(await mobileClient[name]({ body: input, viewerAccessToken: s.viewerAccessToken })));
        } else {
          if (ctx.sessionId && ctx.sessionId !== c.alias || c.sessionId) unavailable();
          if (name === "qrOffer") {
            result = validateMobileResponse(name, closedServerValue(await mobileClient[name]({ body: input })));
            if (c.offer && canonical(c.offer) !== canonical(result) || c.phone) unavailable();
            c.offer = result;
          } else if (["qrScan", "phoneRecover"].includes(name)) {
            const parsed = await bindPhone(c, input);
            result = validateMobileResponse(name, closedServerValue(await mobileClient[name]({ body: input })));
            if (name === "qrScan") {
              if (result.source !== input.source) unavailable();
              c.phone.revision = result.revision;
            } else {
              if (result.authorizationDigest !== parsed.digest || await phoneExchangeCommitment(input.verifier, manager.cryptoImpl) !== parsed.context.exchangeCommitment) unavailable();
              c.phone.revision = input.revision;
            }
          } else if (name === "phoneExchange") result = await exchange(c, input);
          else if (name === "phoneStatus") {
            await proofs(c, input);
            result = validateMobileResponse(name, closedServerValue(await mobileClient[name]({ body: input })));
            if (result.authorizationDigest !== c.phone.parsed.digest) unavailable();
          } else if (issuance) {
            const p = await proofs(c, input);
            if (name === "issue") { const { deliveryKey: _deliveryKey, ...exchangeBody } = input; await exchange(c, exchangeBody); }
            let presentation;
            c.issuing = true;
            try {
              const issued = closedServerValue(await issuanceClient[name]({ body: input }));
              // Bounded original credential retention covers capacity failure
              // and a logout that overtakes a late committed issuance response.
              c.orphan = issued;
              if (!stillCurrent()) {
                try { await manager.cancelUninstalled(issued); c.orphan = undefined; c.orphanCancelled = true; } catch {}
                unavailable();
              }
              presentation = await manager.install(issued, { subject: p.parsed.semantic.subject,
                expiresAt: Math.min(p.parsed.semantic.expiresAt * 1000, milliseconds(p.parsed.context.expiresAt)), stillCurrent });
              c.orphan = undefined;
            } finally { c.issuing = false; }
            c.alias = presentation.id;
            return json(200, { authenticated: true, subject: presentation.subject, receipt: presentation.receipt, messaging: "not-ready" },
              { "Set-Cookie": serializeHostCookie(SESSION_COOKIE_NAME, presentation.id, presentation.maxAge) });
          } else unavailable();
        }
        if (!stillCurrent()) unavailable();
        return json(200, result);
      });
    } catch { return publicError(); }
  }
  return Object.freeze({ handle, oauthGuard });
}
