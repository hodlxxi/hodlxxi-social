import { randomBytes, webcrypto } from "node:crypto";
import { types } from "node:util";
import { canonical, exact, milliseconds, validateIssuanceResponse, unavailable } from "../../web/social-mobile-protocol-v1.mjs";
import { closedServerValue } from "./ubid-social-mobile-client-v1.mjs";

export const isMobileSession = (v) => v && (Object.hasOwn(v, "kind") || Object.hasOwn(v, "issuanceId"));
export function createMobileSessionManager({ sessions, issuanceClient, mobileClient, now = Date.now, random = randomBytes, capacity = 1024 }) {
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 10000 ||
      ["get", "getForLogout", "getLogoutState", "beginLogout", "create", "delete"].some((name) => typeof Object.getOwnPropertyDescriptor(sessions ?? {}, name)?.value !== "function")) unavailable();
  const aliases = new Map(), cancellations = new Map(), locks = new Map();
  const retained = (id) => sessions.getForLogout(id);
  const sweep = () => {
    for (const [id, item] of cancellations) if (item.until <= now()) {
      // Dropping bounded retry state must never restore a locally denied
      // desktop presentation whose ordinary TTL can exceed this retention.
      if (retained(id) === item.original) sessions.delete(id);
      cancellations.delete(id);
    }
    for (const [id, alias] of aliases) if (!retained(alias)) aliases.delete(id);
  };
  async function serial(key, fn) {
    if (locks.size >= capacity && !locks.has(key)) unavailable();
    const before = locks.get(key) ?? Promise.resolve();
    const result = before.catch(() => {}).then(fn);
    locks.set(key, result);
    try { return await result; } finally { if (locks.get(key) === result) locks.delete(key); }
  }
  const receiptOf = (s) => ({ schema: "hodlxxi.social_session_issuance.v1", version: 1, issuanceId: s.issuanceId,
    issuedAt: new Date(s.issuedAt).toISOString().replace(".000Z", "Z"), expiresAt: new Date(s.expiresAt).toISOString().replace(".000Z", "Z") });
  async function read(id) {
    sweep();
    const original = sessions.get(id);
    if (!original || cancellations.has(id)) return null;
    if (!isMobileSession(original)) return original;
    try {
      if (types.isProxy(original)) unavailable();
      exact(original, ["kind", "subject", "viewerAccessToken", "issuanceId", "issuedAt", "expiresAt"]);
      if (original.kind !== "ubid-mobile-v1") unavailable();
      const current = validateIssuanceResponse("resolve", closedServerValue(await issuanceClient.resolve({
        body: { issuanceId: original.issuanceId }, viewerAccessToken: original.viewerAccessToken })));
      if (current.subject !== original.subject || canonical(current.receipt) !== canonical(receiptOf(original)) ||
          sessions.get(id) !== original || cancellations.has(id) || original.expiresAt <= now()) return null;
      return original;
    } catch { return null; }
  }
  async function install(response, { subject, expiresAt, stillCurrent }) {
    if (types.isProxy(response)) unavailable();
    const result = validateIssuanceResponse("issue", closedServerValue(response));
    if (!result.currentActive || result.subject !== subject || milliseconds(result.receipt.expiresAt) > expiresAt) unavailable();
    return serial(result.receipt.issuanceId, async () => {
      sweep();
      const current = validateIssuanceResponse("resolve", closedServerValue(await issuanceClient.resolve({
        body: { issuanceId: result.receipt.issuanceId }, viewerAccessToken: result.viewerAccessToken })));
      if (current.subject !== subject || canonical(current.receipt) !== canonical(result.receipt) || !stillCurrent()) unavailable();
      const issuedAt = milliseconds(result.receipt.issuedAt), end = milliseconds(result.receipt.expiresAt);
      const maxAge = Math.floor((end - now()) / 1000);
      if (issuedAt > now() || maxAge < 1) unavailable();
      let id = aliases.get(result.receipt.issuanceId);
      if (id) {
        const old = sessions.get(id);
        if (!old || cancellations.has(id) || old.subject !== subject || old.viewerAccessToken !== result.viewerAccessToken ||
            canonical(receiptOf(old)) !== canonical(result.receipt)) unavailable();
      } else {
        id = random(32).toString("base64url");
        if (!sessions.create(id, { kind: "ubid-mobile-v1", subject, viewerAccessToken: result.viewerAccessToken,
          issuanceId: result.receipt.issuanceId, issuedAt, expiresAt: end })) unavailable();
        aliases.set(result.receipt.issuanceId, id);
      }
      return Object.freeze({ id, maxAge, receipt: result.receipt, subject });
    });
  }
  async function logout(id) {
    sweep();
    // Install denial in the already allocated session slot BEFORE checking
    // retry/serialization capacity or awaiting upstream. Overflow retains the
    // same original credential in that bounded slot, never in an unbounded map.
    const pending = cancellations.get(id) ?? sessions.getLogoutState(id) ?? sessions.beginLogout(id);
    if (!pending) unavailable();
    if (!cancellations.has(id) && cancellations.size < capacity) cancellations.set(id, pending);
    return serial(`logout:${id}`, async () => {
      if (!pending.confirmed) {
        const s = pending.original;
        if (isMobileSession(s)) {
          const ack = validateIssuanceResponse("revoke", closedServerValue(await issuanceClient.revoke({
            body: { issuanceId: s.issuanceId }, viewerAccessToken: s.viewerAccessToken })));
          if (ack.issuanceId !== s.issuanceId) unavailable();
        } else {
          const { validateMobileResponse } = await import("../../web/social-mobile-protocol-v1.mjs");
          validateMobileResponse("oauthInvalidate", closedServerValue(await mobileClient.oauthInvalidate({ body: {}, viewerAccessToken: s.viewerAccessToken })));
        }
        pending.confirmed = true;
      }
      // A full retry map is not an error: keep the denied slot for bounded
      // exact acknowledgement retries. When the map owns it, free the slot.
      if (cancellations.get(id) === pending && retained(id) === pending.original) sessions.delete(id);
      return true;
    });
  }
  async function capabilityRead(id) {
    const s = await read(id);
    return s ? Object.freeze({ subject: s.subject, viewerAccessToken: s.viewerAccessToken, issuedAt: s.issuedAt, expiresAt: s.expiresAt }) : null;
  }
  async function cancelUninstalled(response) {
    const r = validateIssuanceResponse("issue", closedServerValue(response));
    if (!r.currentActive) unavailable();
    const ack = validateIssuanceResponse("revoke", closedServerValue(await issuanceClient.revoke({ body: { issuanceId: r.receipt.issuanceId }, viewerAccessToken: r.viewerAccessToken })));
    if (ack.issuanceId !== r.receipt.issuanceId) unavailable();
    return true;
  }
  return Object.freeze({ read, capabilityRead, install, logout, cancelUninstalled, retained, serial, cryptoImpl: webcrypto });
}
