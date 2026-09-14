// Frozen UBID a8c409dbe4c900cc8f99c08346cd15bf83604336 wire vocabulary.
// Parsing public history never authenticates a browser or creates authority.
import { canonicalMessagingDeviceJson as canonical } from "./messaging-device-authorization-v1.mjs";
import { METHODS, parseMobileAuthorization, parseMobileJson } from "./mobile-device-authorization-contract-v1.mjs";

export { canonical };
export const MOBILE_PREFIX = "/internal/v1/social/mobile-authorization";
export const ISSUANCE_PREFIX = "/internal/v1/social/session-issuance";
export const SOCIAL_MOBILE_PREFIX = "/auth/mobile/v1";
export const MOBILE_CSRF_HEADER = "x-hodlxxi-mobile-csrf";
export const VIEWER_HEADER = "X-HODLXXI-Viewer-Authorization";
export const MAX_MOBILE_BYTES = 65536;
export const unavailable = () => { throw new TypeError("mobile authorization unavailable"); };
export const hex64 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
export const bearer = (v) => typeof v === "string" && v.length <= 8192 &&
  /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
export const terminalStates = Object.freeze(["cancelled", "abandoned", "rejected", "expired"]);
const states = ["reserved", "created", "awaiting-approval", "approval-claimed", "accepted", ...terminalStates];
const uuid = (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const qr = (v) => /^hodlxxi-social-pair:v1:[0-9a-f]{64}:[0-9a-f]{64}$/.test(v);

export function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) unavailable();
  const d = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(d).length !== fields.length || fields.some((k) =>
    !d[k]?.enumerable || !Object.hasOwn(d[k], "value"))) unavailable();
  return Object.fromEntries(fields.map((k) => [k, d[k].value]));
}

export function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

export function milliseconds(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) unavailable();
  const result = Date.parse(value);
  if (!Number.isSafeInteger(result) || result < 0 ||
      new Date(result).toISOString() !== value.replace("Z", ".000Z")) unavailable();
  return result;
}

// Reject duplicate decoded member names BEFORE JSON.parse can discard them.
// The scanner also bounds nesting before walking/freezing an untrusted object.
export function parseClosedJson(source, { canonicalOnly = true, maximum = MAX_MOBILE_BYTES, depth = 4 } = {}) {
  if (typeof source !== "string" || !source.length || source.length > maximum || /[^\x20-\x7e\r\n\t]/.test(source)) unavailable();
  let offset = 0;
  const ws = () => { while (/[ \r\n\t]/.test(source[offset] ?? "")) offset++; };
  const string = () => {
    if (source[offset] !== '"') unavailable();
    const start = offset++;
    let escaped = false;
    while (offset < source.length) {
      const c = source[offset++];
      if (!escaped && c === '"') {
        const result = JSON.parse(source.slice(start, offset));
        if (/[^\x20-\x7e]/.test(result)) unavailable();
        return result;
      }
      if (!escaped && c === "\\") escaped = true; else escaped = false;
    }
    unavailable();
  };
  const visit = (level) => {
    if (level > depth) unavailable();
    ws();
    if (source[offset] === '"') { string(); return; }
    if (source[offset] === "{" || source[offset] === "[") {
      const object = source[offset++] === "{";
      const close = object ? "}" : "]";
      const keys = new Set();
      ws();
      if (source[offset] === close) { offset++; return; }
      while (offset < source.length) {
        if (object) {
          const key = string();
          if (keys.has(key) || ["__proto__", "constructor", "prototype"].includes(key)) unavailable();
          keys.add(key); ws();
          if (source[offset++] !== ":") unavailable();
        }
        visit(level + 1); ws();
        const separator = source[offset++];
        if (separator === close) return;
        if (separator !== ",") unavailable();
        ws();
      }
      unavailable();
    }
    const start = offset;
    while (offset < source.length && !/[ \r\n\t,}\]]/.test(source[offset])) offset++;
    if (start === offset) unavailable();
  };
  try {
    visit(0); ws();
    if (offset !== source.length) unavailable();
    const value = JSON.parse(source);
    if (canonicalOnly && canonical(value) !== source) unavailable();
    return freeze(value);
  } catch { unavailable(); }
}

const command = (path, group, fields) => Object.freeze({ path, group, fields: Object.freeze(fields) });
export const MOBILE_COMMANDS = Object.freeze({
  legacyReserve: command("legacy/reserve", "desktop", ["content"]),
  legacyAccept: command("legacy/accept", "desktop", ["operationId", "authorizationDigest", "proof"]),
  legacyStatus: command("legacy/status", "desktop", ["operationId"]),
  legacyClose: command("legacy/close", "desktop", ["operationId", "status"]),
  qrCreate: command("qr/create", "desktop", []),
  qrOffer: command("qr/offer", "phone", ["qr"]),
  qrScan: command("qr/scan", "phone", ["source", "qr", "possessionProof"]),
  qrSnapshot: command("qr/snapshot", "desktop", ["pairingId", "revision"]),
  qrClaim: command("qr/claim", "desktop", ["pairingId", "revision", "authorizationDigest", "humanCode"]),
  qrAccept: command("qr/accept", "desktop", ["pairingId", "revision", "authorizationDigest", "proof"]),
  qrStatus: command("qr/status", "desktop", ["pairingId"]),
  qrClose: command("qr/close", "desktop", ["pairingId", "status"]),
  phoneStatus: command("phone/status", "phone", ["pairingId", "revision", "authorizationDigest", "verifier"]),
  phoneRecover: command("phone/recover", "phone", ["source", "qr", "possessionProof", "verifier", "revision"]),
  phoneExchange: command("phone/exchange", "exchange", ["pairingId", "revision", "authorizationDigest", "verifier"]),
  oauthInvalidate: command("oauth/invalidate", "invalidate", [])
});
export const PROOF_FIELDS = Object.freeze(["pairingId", "revision", "authorizationDigest", "verifier", "deliveryKey"]);
export const ISSUANCE_COMMANDS = Object.freeze({
  issue: command("issue", "issuance", PROOF_FIELDS),
  recover: command("recover", "issuance", PROOF_FIELDS),
  resolve: command("resolve", "issuance", ["issuanceId"]),
  revoke: command("revoke", "issuance", ["issuanceId"])
});

export function validateCommand(spec, value) {
  const result = exact(value, spec.fields);
  for (const [k, v] of Object.entries(result)) {
    if (typeof v !== "string") unavailable();
    const valid = ["source", "proof", "content"].includes(k) ? v.length > 0 && v.length <= 16384 && !/[^\x20-\x7e]/.test(v)
      : k === "operationId" ? uuid(v) : k === "qr" ? qr(v)
      : k === "humanCode" ? /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/.test(v)
      : k === "status" ? ["cancelled", "abandoned", "rejected"].includes(v) : hex64(v);
    if (!valid) unavailable();
  }
  return freeze(result);
}

const versioned = (value, schema, fields) => {
  const result = exact(value, ["schema", "version", ...fields]);
  if (result.schema !== schema || result.version !== 1) unavailable();
  return result;
};
const hexes = (value, fields) => { if (fields.some((k) => !hex64(value[k]))) unavailable(); };
export function validateReceipt(value) {
  const r = versioned(value, "hodlxxi.social_session_issuance.v1", ["issuanceId", "issuedAt", "expiresAt"]);
  hexes(r, ["issuanceId"]);
  const start = milliseconds(r.issuedAt), end = milliseconds(r.expiresAt);
  if (end <= start || end - start > 300000) unavailable();
  return freeze(r);
}

export function validateIssuanceResponse(name, value) {
  if (name === "revoke") {
    const r = versioned(value, "hodlxxi.social_session_revocation.v1", ["issuanceId", "status"]);
    if (!hex64(r.issuanceId) || r.status !== "revoked") unavailable();
    return freeze(r);
  }
  const r = exact(value, name === "resolve" ? ["receipt", "subject", "currentActive"]
    : ["receipt", "subject", "currentActive", "viewerAccessToken"]);
  r.receipt = validateReceipt(r.receipt);
  if (r.currentActive === true) {
    if (!hex64(r.subject) || name !== "resolve" && !bearer(r.viewerAccessToken)) unavailable();
  } else if (name === "resolve" || r.currentActive !== false || r.subject !== null || r.viewerAccessToken !== null) unavailable();
  return freeze(r);
}

export function validateAcceptance(value) {
  const r = versioned(value, "hodlxxi.social_mobile_authorization_acceptance.v1", ["authorizationDigest", "bindingId", "subject", "requestId"]);
  hexes(r, ["authorizationDigest", "bindingId", "subject", "requestId"]);
  return freeze(r);
}
export function validateOffer(value) {
  const r = versioned(value, "hodlxxi.social_mobile_pairing_offer.v1", ["pairingId", "secretCommitment", "desktopContext", "subject", "createdAt", "expiresAt", "revision", "status"]);
  hexes(r, ["pairingId", "secretCommitment", "desktopContext", "subject", "revision"]);
  const start = milliseconds(r.createdAt), end = milliseconds(r.expiresAt);
  if (end <= start || end - start > 300000 || !["created", ...terminalStates].includes(r.status)) unavailable();
  return freeze(r);
}

export function validateHandoff(value) {
  const r = versioned(value, "hodlxxi.social_mobile_handoff_delivery.v1", ["identity", "operation", "revision", "consumedAt", "delivery", "freshIssuanceAuthorized"]);
  const i = versioned(r.identity, "hodlxxi.social_phone_session_exchange_identity.v1", ["pairingId", "authorizationDigest", "bindingId", "deviceId", "subject", "requestId", "exchangeCommitment", "expiresAt"]);
  hexes(i, ["pairingId", "authorizationDigest", "bindingId", "deviceId", "subject", "requestId", "exchangeCommitment"]);
  if (!hex64(r.revision) || !["register", "rotate", "adopt"].includes(r.operation) ||
      !["created", "recovered"].includes(r.delivery) || r.freshIssuanceAuthorized !== false ||
      milliseconds(r.consumedAt) >= milliseconds(i.expiresAt)) unavailable();
  r.identity = i;
  return freeze(r);
}

export function validateMobileResponse(name, value) {
  if (["legacyAccept", "qrAccept"].includes(name)) return validateAcceptance(value);
  if (name === "qrOffer") {
    const r = validateOffer(value);
    if (r.status !== "created") unavailable();
    return r;
  }
  if (name === "qrCreate") {
    const r = versioned(value, "hodlxxi.social_mobile_pairing_creation.v1", ["offer", "qr"]);
    r.offer = validateOffer(r.offer);
    if (typeof r.qr !== "string" || !qr(r.qr) || r.qr.split(":")[2] !== r.offer.pairingId || r.offer.status !== "created") unavailable();
    return freeze(r);
  }
  if (["qrScan", "qrSnapshot"].includes(name)) {
    if (Object.getOwnPropertyDescriptor(value ?? {}, "schema")?.value === "hodlxxi.social_mobile_pairing_offer.v1" && name === "qrSnapshot") return validateOffer(value);
    const r = versioned(value, "hodlxxi.social_mobile_pairing_snapshot.v1", ["source", "revision", "status", "acceptance"]);
    if (!hex64(r.revision) || typeof r.source !== "string" || !r.source.length || r.source.length > 16384 ||
        !["awaiting-approval", "approval-claimed", "accepted", ...terminalStates].includes(r.status)) unavailable();
    parseClosedJson(r.source, { maximum: 16384 });
    if (r.status === "accepted") r.acceptance = validateAcceptance(r.acceptance);
    else if (r.acceptance !== null) unavailable();
    return freeze(r);
  }
  if (name === "legacyReserve") {
    const r = versioned(value, "hodlxxi.social_mobile_legacy_reservation.v1", ["challenge", "loginContext", "authorizationDigest", "expiresAt"]);
    if (typeof r.challenge !== "string" || !uuid(r.challenge)) unavailable();
    hexes(r, ["loginContext", "authorizationDigest"]); milliseconds(r.expiresAt);
    return freeze(r);
  }
  if (name === "oauthInvalidate") {
    const r = versioned(value, "hodlxxi.social_mobile_generation_invalidation.v1", ["status"]);
    if (r.status !== "invalidated") unavailable();
    return freeze(r);
  }
  if (name === "phoneExchange") return validateHandoff(value);
  if (["legacyClose", "qrClose", "qrClaim"].includes(name)) {
    const r = exact(value, ["status"]);
    if (!(name === "qrClaim" ? ["approval-claimed"] : terminalStates).includes(r.status)) unavailable();
    return freeze(r);
  }
  if (!["legacyStatus", "qrStatus", "phoneStatus", "phoneRecover"].includes(name)) unavailable();
  const r = exact(value, ["authorizationDigest", "status"]);
  if (r.authorizationDigest !== null && !hex64(r.authorizationDigest) ||
      ![...states, ...(name === "phoneRecover" ? ["never-accepted"] : [])].includes(r.status)) unavailable();
  return freeze(r);
}

// Historical inspection verifies the signed preimage's identity, not its current
// authority. Fresh admission/resolve always belongs to UBID and its real clock.
export async function inspectPhoneSource(source, cryptoImpl = globalThis.crypto) {
  const envelope = parseClosedJson(source, { maximum: 16384 });
  const content = parseClosedJson(envelope.content, { maximum: 8192 });
  const claim = content.authorization ?? content.adoption;
  const subject = claim?.subject ?? claim?.bindingRecord?.subject;
  const at = milliseconds(claim?.issuedAt) / 1000;
  return parseMobileAuthorization(source, { subject, expectedMethod: METHODS.qr, now: at, cryptoImpl });
}
