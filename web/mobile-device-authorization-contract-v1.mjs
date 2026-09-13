// Dormant protocol foundation. Importing this module never acquires a signer,
// opens storage, creates a session, or performs a network operation.
import {
  canonicalMessagingDeviceJson as canonical,
  inspectMessagingDeviceAuthorizationClaim,
  MESSAGING_DEVICE_EVENT_KIND,
  MESSAGING_DEVICE_EVENT_PURPOSE,
  MESSAGING_DEVICE_SIGNATURE_FORMAT
} from "./messaging-device-authorization-v1.mjs";
import { computeNostrEventId, verifyNostrEvent } from "./nostr-event-verifier.mjs";

export const MOBILE_AUTHORIZATION_SCHEMA = "hodlxxi.social_messaging_device_authorization_method.v1";
export const MOBILE_AUTHORIZATION_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V1";
export const QR_APPROVAL_PURPOSE = "hodlxxi-social-messaging-device-qr-approval-v1";
export const METHODS = Object.freeze({ nostr: "nostr_event_v1", legacy: "legacy_challenge_v1", qr: "qr_desktop_v1" });
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const QR_PREFIX = "hodlxxi-social-pair:v1:";
const deny = () => { throw new TypeError("mobile device authorization unavailable"); };
const hex = (v) => { if (typeof v !== "string" || !HEX.test(v)) deny(); return v; };
const freeze = (v) => {
  if (v && typeof v === "object") { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
};
const exact = (v, fields) => {
  if (!v || Object.getPrototypeOf(v) !== Object.prototype) deny();
  const descriptors = Object.getOwnPropertyDescriptors(v);
  if (Reflect.ownKeys(descriptors).length !== fields.length || fields.some((f) =>
    !descriptors[f]?.enumerable || !Object.hasOwn(descriptors[f], "value"))) deny();
  return Object.fromEntries(fields.map((f) => [f, descriptors[f].value]));
};
const second = (v) => {
  if (typeof v !== "string" || !ISO.test(v)) deny();
  const t = Date.parse(v);
  if (!Number.isSafeInteger(t) || new Date(t).toISOString() !== v.replace("Z", ".000Z")) deny();
  return t / 1000;
};
const bytes = (v) => Uint8Array.from(hex(v).match(/../g), (b) => Number.parseInt(b, 16));
const toHex = (v) => [...new Uint8Array(v)].map((b) => b.toString(16).padStart(2, "0")).join("");
export const mobileDigest = async (v, cryptoImpl = globalThis.crypto) =>
  toHex(await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(v)));

// Canonical round-trip rejects duplicates, unknown fields, alternate encodings,
// whitespace and private-key-bearing objects before any effectful seam is used.
export function parseMobileJson(source) {
  if (typeof source !== "string" || !source.length || source.length > 16384 || /[^\x20-\x7e]/.test(source)) deny();
  let value;
  try { value = JSON.parse(source); } catch { deny(); }
  if (canonical(value) !== source) deny();
  return freeze(value);
}

const validatePublicKey = (value) => {
  hex(value);
  const n = BigInt("0x" + value.match(/../g).reverse().join(""));
  if (n <= 1n || n >= (1n << 255n) - 20n || [
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900"
  ].includes(value)) deny();
};

export async function parseMobileAuthorization(source, {
  subject, proposal, expectedMethod, now, cryptoImpl = globalThis.crypto
} = {}) {
  hex(subject);
  if (!Object.values(METHODS).includes(expectedMethod) || !Number.isSafeInteger(now)) deny();
  const value = exact(parseMobileJson(source), ["content", "context", "domain", "method", "schema", "version"]);
  if (value.schema !== MOBILE_AUTHORIZATION_SCHEMA || value.version !== 1 ||
      value.domain !== MOBILE_AUTHORIZATION_DOMAIN || value.method !== expectedMethod) deny();
  const semantic = await inspectMessagingDeviceAuthorizationClaim(value.content, { subject, proposal, cryptoImpl });
  validatePublicKey(semantic.binding.publicKey);
  if (semantic.issuedAt < 0 || semantic.issuedAt > now || now >= semantic.expiresAt) deny();
  if (value.method === METHODS.nostr) {
    if (value.context !== null) deny();
  } else if (value.method === METHODS.legacy) {
    const context = exact(value.context, ["challenge", "loginContext"]);
    if (typeof context.challenge !== "string" || !UUID.test(context.challenge)) deny();
    hex(context.loginContext);
  } else {
    const context = exact(value.context, [
      "createdAt", "desktopContext", "exchangeCommitment", "expiresAt", "pairingId", "secretCommitment"
    ]);
    [context.desktopContext, context.exchangeCommitment, context.pairingId, context.secretCommitment].forEach(hex);
    const start = second(context.createdAt), end = second(context.expiresAt);
    if (end <= start || end - start > 300 || start > semantic.issuedAt ||
        semantic.expiresAt > end || now >= end) deny();
  }
  const digest = await mobileDigest(source, cryptoImpl);
  const replayIds = ["request:" + semantic.requestId, "authorization:" + digest];
  if (value.method === METHODS.legacy) replayIds.push("legacy-challenge:" + value.context.challenge);
  if (value.method === METHODS.qr) replayIds.push("pairing:" + value.context.pairingId);
  return freeze({ ...value, digest, semantic, replayIds });
}

export async function createMobileAuthorization(content, context, method, options) {
  // Context is parsed from canonical text; object accessors never enter a hash.
  const source = canonical({ content, context: parseMobileJson(context), domain: MOBILE_AUTHORIZATION_DOMAIN,
    method, schema: MOBILE_AUTHORIZATION_SCHEMA, version: 1 });
  await parseMobileAuthorization(source, { ...options, expectedMethod: method });
  return source;
}

export function createPairingQr(pairingId, secret) {
  return QR_PREFIX + hex(pairingId) + ":" + hex(secret);
}
export function parsePairingQr(value) {
  if (typeof value !== "string" || !value.startsWith(QR_PREFIX)) deny();
  const parts = value.slice(QR_PREFIX.length).split(":");
  if (parts.length !== 2) deny();
  return Object.freeze({ pairingId: hex(parts[0]), secret: hex(parts[1]) });
}
export const pairingSecretCommitment = (secret, cryptoImpl) =>
  mobileDigest("HODLXXI_SOCIAL_PAIRING_SECRET_V1\u0000" + hex(secret), cryptoImpl);
export const phoneExchangeCommitment = (verifier, cryptoImpl) =>
  mobileDigest("HODLXXI_SOCIAL_PHONE_EXCHANGE_V1\u0000" + hex(verifier), cryptoImpl);

export function pairingComparisonCode(digest) {
  return hex(digest).slice(0, 12).toUpperCase().match(/.{4}/g).join("-");
}

export async function pairingPossessionProof(secret, transcriptDigest, cryptoImpl = globalThis.crypto) {
  const key = await cryptoImpl.subtle.importKey("raw", bytes(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await cryptoImpl.subtle.sign("HMAC", key,
    new TextEncoder().encode("HODLXXI_SOCIAL_PAIRING_POSSESSION_V1\u0000" + hex(transcriptDigest))));
}

export async function verifyPairingScan(source, { qr, possessionProof, ...options }) {
  const parsed = await parseMobileAuthorization(source, { ...options, expectedMethod: METHODS.qr });
  const locator = parsePairingQr(qr);
  if (locator.pairingId !== parsed.context.pairingId ||
      await pairingSecretCommitment(locator.secret, options.cryptoImpl) !== parsed.context.secretCommitment ||
      await pairingPossessionProof(locator.secret, parsed.digest, options.cryptoImpl) !== hex(possessionProof)) deny();
  // A valid scan is only a pending transcript. It is never a login grant.
  return Object.freeze({ state: "awaiting-approval", transcriptDigest: parsed.digest,
    comparisonCode: pairingComparisonCode(parsed.digest) });
}

export async function mobileUnsignedEvent(source, options) {
  const parsed = await parseMobileAuthorization(source, options);
  if (parsed.method === METHODS.legacy) deny();
  const qr = parsed.method === METHODS.qr;
  const content = qr ? source : parsed.content;
  const tags = [
    ["purpose", qr ? QR_APPROVAL_PURPOSE : MESSAGING_DEVICE_EVENT_PURPOSE],
    ["semantic-digest", qr ? parsed.digest : parsed.semantic.digest],
    ["request-id", parsed.semantic.requestId],
    ["action", parsed.semantic.action]
  ];
  if (qr) tags.push(["pairing-id", parsed.context.pairingId], ["transcript", parsed.digest]);
  const event = { content, created_at: parsed.semantic.issuedAt, kind: MESSAGING_DEVICE_EVENT_KIND, tags };
  const id = await computeNostrEventId({ ...event, pubkey: parsed.semantic.subject,
    id: "0".repeat(64), sig: "0".repeat(128) }, { cryptoImpl: options.cryptoImpl });
  return freeze({ unsignedEvent: event, eventId: id, signatureFormat: MESSAGING_DEVICE_SIGNATURE_FORMAT });
}

export async function verifyMobileEvent(source, signedEvent, options) {
  const expected = await mobileUnsignedEvent(source, options);
  let verified;
  try { verified = await verifyNostrEvent(signedEvent, { cryptoImpl: options.cryptoImpl }); } catch { deny(); }
  if (verified.pubkey !== options.subject || verified.id !== expected.eventId ||
      canonical({ content: verified.content, created_at: verified.created_at, kind: verified.kind, tags: verified.tags }) !==
        canonical(expected.unsignedEvent)) deny();
  return verified;
}

// Public retry material only. Signature validation never permits a method switch.
export async function parseMobileEventRetry(source, retrySource, options) {
  const retry = exact(parseMobileJson(retrySource), ["authorization", "signedEvent", "signatureFormat"]);
  if (retry.authorization !== source || retry.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT) deny();
  return verifyMobileEvent(source, retry.signedEvent, options);
}

export async function legacyChallengeSigningDigest(challenge, cryptoImpl = globalThis.crypto) {
  if (typeof challenge !== "string" || !UUID.test(challenge)) deny();
  // Bitcoin Core verifymessage: CompactSize(magic), magic, CompactSize(message),
  // message, then SHA256 twice. The LEGACY UUID is exactly 36 ASCII bytes.
  const magic = new TextEncoder().encode("Bitcoin Signed Message:\n");
  const message = new TextEncoder().encode(challenge);
  const preimage = new Uint8Array([magic.length, ...magic, message.length, ...message]);
  const first = await cryptoImpl.subtle.digest("SHA-256", preimage);
  return toHex(await cryptoImpl.subtle.digest("SHA-256", first));
}

export async function parseLegacyChallengeSubmission(source, submissionSource, options) {
  const parsed = await parseMobileAuthorization(source, { ...options, expectedMethod: METHODS.legacy });
  const submission = exact(parseMobileJson(submissionSource), [
    "authorizationDigest", "challenge", "compressedPublicKey", "loginContext", "method", "signature"
  ]);
  if (submission.method !== METHODS.legacy || submission.authorizationDigest !== parsed.digest ||
      submission.challenge !== parsed.context.challenge || submission.loginContext !== parsed.context.loginContext ||
      typeof submission.compressedPublicKey !== "string" || !/^0[23][0-9a-f]{64}$/.test(submission.compressedPublicKey) ||
      submission.compressedPublicKey.slice(2) !== options.subject || typeof submission.signature !== "string" ||
      !/^[A-Za-z0-9+/]{87}=$/.test(submission.signature)) deny();
  let signature;
  try { signature = Uint8Array.from(atob(submission.signature), (c) => c.charCodeAt(0)); } catch { deny(); }
  if (signature.length !== 65 || signature[0] < 31 || signature[0] > 34 ||
      btoa(String.fromCharCode(...signature)) !== submission.signature) deny();
  // This is structural inspection, not Bitcoin signature verification. Only
  // UBID's verified, atomically consumed challenge may authorize the device.
  return freeze({ ...submission, signingDigest: await legacyChallengeSigningDigest(submission.challenge, options.cryptoImpl) });
}

// Identity metadata for the confidential session issuer, never a bearer grant.
// The browser must subsequently reconcile its exact authoritative binding using
// its own newly created Social session before showing the device as ready.
export async function parsePhoneSessionExchangeIdentity(source, { authorization, verifier, ...options }) {
  const parsed = await parseMobileAuthorization(authorization, { ...options, expectedMethod: METHODS.qr });
  if (parsed.semantic.action === "revoke") deny();
  const commitment = await phoneExchangeCommitment(verifier, options.cryptoImpl);
  if (commitment !== parsed.context.exchangeCommitment) deny();
  const expected = {
    schema: "hodlxxi.social_phone_session_exchange_identity.v1", version: 1,
    pairingId: parsed.context.pairingId, authorizationDigest: parsed.digest,
    bindingId: parsed.semantic.bindingId, deviceId: parsed.semantic.binding.deviceId,
    subject: parsed.semantic.subject, requestId: parsed.semantic.requestId,
    exchangeCommitment: commitment,
    expiresAt: new Date(parsed.semantic.expiresAt * 1000).toISOString().replace(".000Z", "Z")
  };
  if (canonical(expected) !== source) deny();
  return freeze(expected);
}
