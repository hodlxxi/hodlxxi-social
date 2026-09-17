// CONTRACT ONLY. Candidate bytes are not authentication or an admission grant.
// No proof algorithm is approved. Even explicit enablement cannot admit a request.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import { parseCanonicalMessageEnvelopeWireV1 } from "./message-envelope-v128f1.mjs";

export const DEVICE_ADMISSION_ENABLED = false;
export const APPROVED_DEVICE_PROOF_PROFILE = null;
export const MAX_DEVICE_CHALLENGE_LIFETIME_MS = 60_000;
export const DEVICE_REQUEST_SCHEMA = "hodlxxi.social_messaging_device_request_candidate.v1";
export const DEVICE_CHALLENGE_SCHEMA = "hodlxxi.social_messaging_device_challenge_candidate.v1";
export const RECIPIENT_SELF_SCHEMA = "hodlxxi.social_messaging_recipient_self_request.v1";
export const DEVICE_CHALLENGE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1";

const CONTEXT_FIELDS = ["audience", "bindingId", "bindingVersion", "deviceId", "sessionBinding", "subject"];
const REQUEST_FIELDS = [...CONTEXT_FIELDS, "bodyDigest", "method", "operation", "path", "recipientHandle", "schema", "version"];
const CHALLENGE_FIELDS = ["challengeId", "domain", "expiresAt", "issuedAt", "request", "schema", "version"];
const fail = () => { throw new TypeError("messaging device admission unavailable"); };
const canonical = (value) => JSON.stringify(value, Object.keys(value).sort());
const hash = (domain, wire) => createHash("sha256").update(domain + "\0", "ascii").update(wire, "ascii").digest("hex");
const hex = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const validPath = (v) => typeof v === "string" && v.length <= 160 && /^\/[a-z0-9]+(?:[/-][a-z0-9]+)*$/.test(v);

function enabled(options) {
  if (!options || typeof options !== "object" || isProxy(options)) fail();
  const descriptor = Object.getOwnPropertyDescriptor(options, "enabled");
  if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.value !== true) fail();
}

function parse(wire, fields, maximum) {
  if (typeof wire !== "string" || wire.length > maximum || /[^\x20-\x7e]/.test(wire)) fail();
  const value = JSON.parse(wire);
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field)) ||
      canonical(value) !== wire) fail();
  // Exact reserialization also rejects duplicate keys, alternate escapes and numbers.
  return value;
}

function context(value) {
  for (const field of ["bindingId", "deviceId", "sessionBinding", "subject"]) if (!hex(value[field])) fail();
  if (!Number.isInteger(value.bindingVersion) || value.bindingVersion < 1 || value.bindingVersion > 1024 ||
      typeof value.audience !== "string" || value.audience.length > 255) fail();
  const url = new URL(value.audience);
  if (url.protocol !== "https:" || url.origin !== value.audience || url.username || url.password) fail();
}

function handle(value) {
  if (typeof value !== "string" || !/^d_[A-Za-z0-9_-]{22}$/.test(value) ||
      Buffer.from(value.slice(2), "base64url").toString("base64url") !== value.slice(2)) fail();
}

function request(wire) {
  const value = parse(wire, REQUEST_FIELDS, 2048);
  context(value);
  if (value.schema !== DEVICE_REQUEST_SCHEMA || value.version !== 1 || value.method !== "POST" ||
      !validPath(value.path) ||
      typeof value.bodyDigest !== "string" || !/^hodlxxi-social-device-request-body-v1-sha256:[0-9a-f]{64}$/.test(value.bodyDigest)) fail();
  if (value.operation === "ciphertext-submit") {
    if (value.recipientHandle !== null) fail();
  } else if (value.operation === "recipient-self-read") {
    handle(value.recipientHandle);
  } else fail();
  return Object.freeze(value);
}

/** Construct untrusted candidate bytes from a CONFIDENTIAL context and actual wire.
 * A future adapter must obtain context from current authentication/authority,
 * never browser claims. sessionBinding is a non-bearer per-session-generation
 * correlation value, NOT a cookie, token, token hash or a new login credential.
 */
export function createDeviceRequestCandidateV1(contextWire, operation, method, path, bodyWire, options = {}) {
  try {
    enabled(options);
    if (method !== "POST" || !validPath(path)) fail();
    const value = parse(contextWire, CONTEXT_FIELDS, 1024);
    context(value);
    let recipientHandle = null;
    if (operation === "ciphertext-submit") {
      // Keep the existing canonical envelope bytes; do not sort or rewrite them.
      if (typeof bodyWire !== "string") fail();
      parseCanonicalMessageEnvelopeWireV1(bodyWire);
    } else if (operation === "recipient-self-read") {
      const body = parse(bodyWire, ["deviceHandle", "schema", "version"], 256);
      if (body.schema !== RECIPIENT_SELF_SCHEMA || body.version !== 1) fail();
      handle(body.deviceHandle);
      recipientHandle = body.deviceHandle;
    } else fail();
    const wire = canonical({ ...value, bodyDigest: "hodlxxi-social-device-request-body-v1-sha256:" +
      hash("HODLXXI_SOCIAL_DEVICE_REQUEST_BODY_V1", bodyWire), method, operation, path, recipientHandle,
    schema: DEVICE_REQUEST_SCHEMA, version: 1 });
    request(wire);
    return wire;
  } catch { fail(); }
}

export function parseDeviceRequestCandidateV1(wire, options = {}) {
  try { enabled(options); return request(wire); } catch { fail(); }
}

/** Serialization only: does not issue, reserve, authenticate, or persist a challenge. */
export function createDeviceChallengeCandidateV1(requestWire, challengeId, issuedAt, expiresAt, options = {}) {
  try {
    enabled(options);
    request(requestWire);
    if (!hex(challengeId) || !integer(issuedAt) || !integer(expiresAt)) fail();
    const wire = canonical({ challengeId, domain: DEVICE_CHALLENGE_DOMAIN, expiresAt, issuedAt,
      request: requestWire, schema: DEVICE_CHALLENGE_SCHEMA, version: 1 });
    challenge(wire);
    return wire;
  } catch { fail(); }
}

function challenge(wire) {
  const value = parse(wire, CHALLENGE_FIELDS, 4096);
  if (value.schema !== DEVICE_CHALLENGE_SCHEMA || value.version !== 1 || value.domain !== DEVICE_CHALLENGE_DOMAIN ||
      !hex(value.challengeId) || !integer(value.issuedAt) || !integer(value.expiresAt) ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > MAX_DEVICE_CHALLENGE_LIFETIME_MS) fail();
  request(value.request);
  return Object.freeze(value);
}

/** Structural/temporal comparison only. A matching candidate grants no authority. */
export function inspectDeviceChallengeCandidateV1(challengeWire, actualRequestWire, now, options = {}) {
  try {
    enabled(options);
    const value = challenge(challengeWire);
    request(actualRequestWire);
    if (value.request !== actualRequestWire || !integer(now) || now < value.issuedAt || now >= value.expiresAt) fail();
    return value;
  } catch { fail(); }
}

export function digestDeviceChallengeCandidateV1(wire, options = {}) {
  try {
    enabled(options);
    challenge(wire);
    return "hodlxxi-social-device-challenge-v1-sha256:" + hash("HODLXXI_SOCIAL_DEVICE_CHALLENGE_DIGEST_V1", wire);
  } catch { fail(); }
}

/**
 * Future verifier interfaces; NO implementations or runtime injection exist here.
 * All ports run inside ONE trusted transaction/authority owner. See the ADR for
 * exact outputs, lock/recheck rules, source provenance and cross-owner limits.
 *
 * @typedef {object} VerifiedDeviceRequestProofV1
 * @property {string} challengeDigest
 * @property {string} proofProfile
 * @property {string} sessionBinding
 * @property {string} subject
 * @property {string} deviceId
 * @property {string} bindingId
 * @property {number} bindingVersion
 *
 * @typedef {object} DeviceProofVerifierV1
 * @property {function(string, unknown, object): Promise<VerifiedDeviceRequestProofV1>} verifyInTransaction
 *   (exactChallengeWire, profileSpecificProof, lockedAuthority) -> exact verified
 *   transcript/session/subject/device/binding/profile result, never boolean.
 *
 * @typedef {object} DeviceAdmissionAuthorityV1
 * @property {function(object): Promise<object>} lockAndReadCurrent
 *   Trusted authentication context -> current session, Current-Full, complete
 *   exact binding and accepted evidence, plus approved proof-key association.
 * @property {function(string, object): Promise<object>} resolveRecipientSelf
 *   (one opaque handle, lockedAuthority) -> one exact confidential owner match.
 * @property {function(string): Promise<object>} readIssuedChallenge
 *   challengeId -> one immutable reserved transcript, never caller-shaped JSON.
 * @property {function(object): Promise<void>} consumeAndApply
 *   Recheck current authority/time, consume globally unique challenge ID and
 *   perform exact authorized operation atomically. No reusable admission token.
 */

/** @returns {never} No option, evidence, session or injected verifier can enable admission. */
export function admitMessagingDeviceRequestV1(_attempt, _options = {}) {
  fail();
}
