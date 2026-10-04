// Dormant pure producer for UBID's exact preaccepted-enrollment V2 statement.
// This module owns no key or direct storage, network or key-discovery I/O,
// grants no authority, consumes no challenge, mutates no association, and is
// deliberately absent from runtime composition.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  projectMessagingDevicePreacceptedEnrollmentV2,
  verifyMessagingDevicePreacceptedEnrollmentV2
} from "./messaging-device-preaccepted-enrollment-v2.mjs";

const safeBuffer = Buffer;
const safeCreateHash = createHash;
const safeIsProxy = isProxy;

export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENTS_V2_ENABLED_DEFAULT =
  false;
export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM =
  "RS256";
export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_TYPE =
  "hodlxxi-social-preaccepted-enrollment-verification-v2+jws";
export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE =
  "social_preaccepted_enrollment_cryptographic_verification_v2";
export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_RESULT =
  "preaccepted-enrollment-v2-bip340-and-ed25519-valid";
export const PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_SCHEMA =
  "hodlxxi.social_preaccepted_enrollment_verification_statement.v2";
export const MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_LIFETIME_MS =
  10_000;
export const MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_BYTES = 4_096;

const VERSION = 2;
const CONSUME_PATH = "/internal/v2/social/device-admission/consume";
const INPUT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2";
const INPUT_DIGEST_PREFIX =
  "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:";
const JTI_DOMAIN =
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2";
const MAX_PROTECTED_HEADER_BYTES = 1_024;
const MAX_PAYLOAD_BYTES = 3_072;
const MAX_INPUT_BYTES = 24_576;
const MAX_CONTEXT_BYTES = 4_096;
const MAX_ENROLLMENT_BYTES = 4_096;
const MAX_AUTHORIZATION_BYTES = 16_384;
const MAX_PRE_ENROLLMENT_BYTES = 8_192;
const INPUT_FIELDS = [
  "acceptanceId", "approvalEvent", "context", "enrollment", "phoneProof",
  "schema", "version"
];
const EVENT_FIELDS = [
  "content", "created_at", "id", "kind", "pubkey", "sig", "tags"
];
const CONTEXT_FIELDS = [
  "approverFullProofId", "approverSessionBinding", "associationId",
  "associationVersion", "attemptId", "audience", "authorityEpoch",
  "bindingId", "bindingVersion", "challengeId", "challengeKind", "deviceId",
  "ed25519PublicKey", "fullProofId", "predecessorAssociationId", "profile",
  "schema", "sessionBinding", "subject", "version",
  "x25519PublicKeyCommitment"
];
const ENROLLMENT_FIELDS = [
  "audience", "deviceId", "domain", "ed25519PublicKey",
  "enrollmentChallengeId", "expiresAt", "issuedAt", "profile", "schema",
  "subject", "version", "x25519BindingId", "x25519BindingVersion",
  "x25519PublicKeyCommitment"
];
const AUTHORIZATION_FIELDS = [
  "content", "context", "domain", "method", "preEnrollment", "schema",
  "version"
];
const AUTHORIZATION_CONTEXT_FIELDS = [
  "createdAt", "desktopContext", "exchangeCommitment", "expiresAt",
  "pairingId", "secretCommitment"
];
const PRE_ENROLLMENT_FIELDS = [
  "bindingAuthorizationDigest", "deviceId", "domain", "ed25519PublicKey",
  "expiresAt", "issuedAt", "pairingId", "preEffectAssociationId",
  "preEffectAssociationState", "preEffectAssociationVersion",
  "preEffectAuthorityEpoch", "profile", "proposedAssociationVersion",
  "proposedAuthorityEpoch", "proposedPredecessorAssociationId", "requestId",
  "schema", "subject", "transitionKind", "version", "x25519BindingId",
  "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const CLAIM_CONTAINER_FIELDS = ["authorization", "domain"];
const LIFECYCLE_FIELDS = [
  "algorithm", "bindingExpiresAt", "bindingRecordSchema",
  "bindingRecordVersion", "bindingValidFrom", "bindingVersion", "deviceId",
  "expiresAt", "issuedAt", "operation", "priorBindingId", "publicKey",
  "requestId", "schema", "subject", "version"
];
const PRODUCER_FIELDS = [
  "approverSessionExpiresAtMs", "contextWire", "expectedAudience",
  "expectedAlgorithm", "expectedClientId", "expectedIssuer", "expectedKid",
  "expectedPurpose", "expectedServicePrincipal", "fullExpiresAtMs",
  "inputWire", "now", "phoneSessionExpiresAtMs", "signer",
  "statementLifetimeMs", "x25519BindingExpiresAtMs"
];
const SIGNER_FIELDS = [
  "algorithm", "audience", "clientId", "issuer", "kid", "purpose",
  "servicePrincipal", "signExact"
];
const GATE_FIELDS = [
  "preacceptedEnrollmentVerificationStatementsV2Enabled"
];
// Security boundary: caller/network bytes, signer behavior, and later-supplied
// public evidence are untrusted. The Node process/executable, Node/OpenSSL
// built-ins, trusted deployment source, package-lock-selected dependencies,
// and intentionally loaded application code are trusted. Arbitrary JavaScript
// rewriting process-wide state is process compromise; process isolation is a
// future architecture. The captures below reduce selected live lookups as
// non-exhaustive, non-normative defense in depth. They are not a complete
// mutable-primordial inventory or an arbitrary monkey-patching guarantee.
const safeApply = Reflect.apply;
const safeArrayIsArray = Array.isArray;
const safeBufferByteLength = safeBuffer.byteLength;
const safeBufferFrom = safeBuffer.from;
const safeBufferToString = safeBuffer.prototype.toString;
const safeDate = Date;
const safeDateParse = Date.parse;
const safeDateToISOString = Date.prototype.toISOString;
const safeJsonParse = JSON.parse;
const safeJsonStringify = JSON.stringify;
const safeNumberIsFinite = Number.isFinite;
const safeNumberIsSafeInteger = Number.isSafeInteger;
const safeObjectCreate = Object.create;
const safeObjectFreeze = Object.freeze;
const safeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const safeObjectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const safeObjectGetPrototypeOf = Object.getPrototypeOf;
const safeObjectHasOwn = Object.hasOwn;
const safeReflectOwnKeys = Reflect.ownKeys;
const safeRegExpExec = RegExp.prototype.exec;
const safeStringCharCodeAt = String.prototype.charCodeAt;
const safeStringSlice = String.prototype.slice;
const safeTypeError = TypeError;
const safeURL = URL;
const safeURLHostname = safeObjectGetOwnPropertyDescriptor(
  safeURL.prototype,
  "hostname"
).get;
const safeWeakMapGet = WeakMap.prototype.get;
const safeWeakMapHas = WeakMap.prototype.has;
const safeWeakMapSet = WeakMap.prototype.set;
const objectPrototype = Object.prototype;
const arrayPrototype = Array.prototype;
const bufferPrototype = safeBuffer.prototype;
const uint8ArrayPrototype = Uint8Array.prototype;
const typedArrayPrototype = safeObjectGetPrototypeOf(uint8ArrayPrototype);
const safeTypedArrayByteLength = safeObjectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteLength"
).get;
const hashPrototype = safeObjectGetPrototypeOf(safeCreateHash("sha256"));
const safeHashDigest = hashPrototype.digest;
const safeHashUpdate = hashPrototype.update;

const CONFIGURED_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/;
const NON_VISIBLE_ASCII = /[^\x21-\x7e]/;
const NON_PRINTABLE_ASCII = /[^\x20-\x7e]/;
const CANONICAL_ISSUER =
  /^https:\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]+))?$/;
const CANONICAL_PORT = /^[1-9][0-9]{0,4}$/;
const DECIMAL_LABEL = /^[0-9]+$/;
const CANONICAL_IPV4_LABEL = /^(0|[1-9][0-9]{0,2})$/;
const NUMERIC_FINAL_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const signerStates = new WeakMap();
const fail = () => {
  throw new safeTypeError(
    "messaging device preaccepted enrollment verification statement v2 unavailable"
  );
};

function regexpMatches(pattern, value) {
  return safeApply(safeRegExpExec, pattern, [value]) !== null;
}

function typedArrayLength(value) {
  return safeApply(safeTypedArrayByteLength, value, []);
}

function hashDigest(parts, outputEncoding) {
  const hash = safeCreateHash("sha256");
  for (let index = 0; index < parts.length; index += 1) {
    safeApply(safeHashUpdate, hash, [parts[index][0], parts[index][1]]);
  }
  return outputEncoding === undefined
    ? safeApply(safeHashDigest, hash, [])
    : safeApply(safeHashDigest, hash, [outputEncoding]);
}

function fieldAllowed(fields, candidate) {
  for (let index = 0; index < fields.length; index += 1) {
    if (fields[index] === candidate) return true;
  }
  return false;
}

function ownData(value, fields) {
  if (
    value === null || typeof value !== "object" || safeArrayIsArray(value) ||
    safeIsProxy(value) || safeObjectGetPrototypeOf(value) !== objectPrototype
  ) fail();
  const descriptors = safeObjectGetOwnPropertyDescriptors(value);
  const keys = safeReflectOwnKeys(descriptors);
  if (keys.length !== fields.length) fail();
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (
      typeof key !== "string" || !fieldAllowed(fields, key) ||
      descriptors[key].enumerable !== true ||
      !safeObjectHasOwn(descriptors[key], "value")
    ) fail();
  }
  const result = safeObjectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (!safeObjectHasOwn(descriptors, field)) fail();
    result[field] = descriptors[field].value;
  }
  return safeObjectFreeze(result);
}

function jsonPrimitive(value) {
  const encoded = safeApply(safeJsonStringify, undefined, [value]);
  if (typeof encoded !== "string") fail();
  return encoded;
}

function canonicalJson(value) {
  if (
    value === null || typeof value === "string" ||
    typeof value === "boolean"
  ) return jsonPrimitive(value);
  if (typeof value === "number") {
    if (!safeNumberIsFinite(value)) fail();
    return jsonPrimitive(value);
  }
  if (typeof value !== "object" || safeIsProxy(value)) fail();
  const descriptors = safeObjectGetOwnPropertyDescriptors(value);
  if (safeArrayIsArray(value)) {
    if (safeObjectGetPrototypeOf(value) !== arrayPrototype) fail();
    const length = value.length;
    const keys = safeReflectOwnKeys(descriptors);
    if (keys.length !== length + 1 || descriptors.length?.value !== length) {
      fail();
    }
    let wire = "[";
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[`${index}`];
      if (
        descriptor === undefined || descriptor.enumerable !== true ||
        !safeObjectHasOwn(descriptor, "value")
      ) fail();
      if (index !== 0) wire += ",";
      wire += canonicalJson(descriptor.value);
    }
    return wire + "]";
  }
  if (safeObjectGetPrototypeOf(value) !== objectPrototype) fail();
  const keys = safeReflectOwnKeys(descriptors);
  const sorted = safeObjectCreate(null);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (
      typeof key !== "string" || descriptors[key].enumerable !== true ||
      !safeObjectHasOwn(descriptors[key], "value")
    ) fail();
    let position = index;
    while (position > 0 && key < sorted[position - 1]) {
      sorted[position] = sorted[position - 1];
      position -= 1;
    }
    sorted[position] = key;
  }
  let wire = "{";
  for (let index = 0; index < keys.length; index += 1) {
    const key = sorted[index];
    if (index !== 0) wire += ",";
    wire += `${jsonPrimitive(key)}:${canonicalJson(descriptors[key].value)}`;
  }
  return wire + "}";
}

function closedVerifiedJson(source, fields, maximum) {
  if (
    typeof source !== "string" || source.length === 0 ||
    safeApply(safeBufferByteLength, safeBuffer, [source, "utf8"]) > maximum ||
    regexpMatches(NON_PRINTABLE_ASCII, source)
  ) fail();
  let parsed;
  try {
    parsed = safeApply(safeJsonParse, undefined, [source]);
  } catch {
    fail();
  }
  const value = ownData(parsed, fields);
  if (canonicalJson(parsed) !== source) fail();
  return value;
}

function integer(value, positive = false) {
  if (
    !safeNumberIsSafeInteger(value) || value < 0 ||
    (positive && value === 0)
  ) fail();
  return value;
}

function decimal(value) {
  let result = 0;
  for (let index = 0; index < value.length; index += 1) {
    result = result * 10 +
      safeApply(safeStringCharCodeAt, value, [index]) - 48;
  }
  return result;
}

function identifier(value) {
  if (
    typeof value !== "string" ||
    !regexpMatches(CONFIGURED_IDENTIFIER, value)
  ) fail();
  return value;
}

function issuer(value) {
  if (
    typeof value !== "string" || value.length > 255 ||
    regexpMatches(NON_VISIBLE_ASCII, value)
  ) fail();
  const match = safeApply(safeRegExpExec, CANONICAL_ISSUER, [value]);
  if (match === null) fail();
  const host = match[1];
  const port = match[2];
  if (
    port !== undefined &&
    (!regexpMatches(CANONICAL_PORT, port) || decimal(port) > 65_535 ||
      port === "443")
  ) fail();
  if (safeApply(safeStringCharCodeAt, host, [0]) === 91) {
    let url;
    try { url = new safeURL(value); } catch { fail(); }
    if (safeApply(safeURLHostname, url, []) !== host) fail();
    return value;
  }
  const labels = safeObjectCreate(null);
  let labelCount = 0;
  let start = 0;
  for (let index = 0; index <= host.length; index += 1) {
    if (
      index === host.length ||
      safeApply(safeStringCharCodeAt, host, [index]) === 46
    ) {
      labels[labelCount] = safeApply(safeStringSlice, host, [start, index]);
      labelCount += 1;
      start = index + 1;
    }
  }
  let ipv4 = labelCount === 4;
  for (let index = 0; index < labelCount; index += 1) {
    if (!regexpMatches(DECIMAL_LABEL, labels[index])) ipv4 = false;
  }
  if (ipv4) {
    for (let index = 0; index < labelCount; index += 1) {
      if (
        !regexpMatches(CANONICAL_IPV4_LABEL, labels[index]) ||
        decimal(labels[index]) > 255
      ) fail();
    }
    return value;
  }
  if (regexpMatches(NUMERIC_FINAL_LABEL, labels[labelCount - 1])) fail();
  for (let index = 0; index < labelCount; index += 1) {
    const label = labels[index];
    if (
      !regexpMatches(DNS_LABEL, label) ||
      (label.length >= 4 &&
        safeApply(safeStringSlice, label, [0, 4]) === "xn--")
    ) fail();
  }
  return value;
}

function statementAudience(value) {
  if (
    typeof value !== "string" || value.length <= CONSUME_PATH.length ||
    safeApply(safeStringSlice, value, [-CONSUME_PATH.length]) !== CONSUME_PATH
  ) fail();
  issuer(safeApply(safeStringSlice, value, [0, -CONSUME_PATH.length]));
  return value;
}

function seconds(value) {
  if (typeof value !== "string" || !regexpMatches(ISO_SECOND, value)) fail();
  const milliseconds = safeDateParse(value);
  if (!safeNumberIsSafeInteger(milliseconds)) fail();
  if (
    safeApply(safeDateToISOString, new safeDate(milliseconds), []) !==
      safeApply(safeStringSlice, value, [0, -1]) + ".000Z"
  ) fail();
  return milliseconds / 1_000;
}

function requireEnabled(options) {
  const value = ownData(options, GATE_FIELDS);
  if (value.preacceptedEnrollmentVerificationStatementsV2Enabled !== true) {
    fail();
  }
}

function signerState(value) {
  if (
    value === null || typeof value !== "object" || safeIsProxy(value) ||
    safeApply(safeWeakMapHas, signerStates, [value]) !== true
  ) fail();
  return safeApply(safeWeakMapGet, signerStates, [value]);
}

function assertConfigured(input, context, signer) {
  if (
    issuer(input.expectedIssuer) !== context.audience ||
    statementAudience(input.expectedAudience) !== input.expectedAudience ||
    identifier(input.expectedClientId) !== input.expectedClientId ||
    identifier(input.expectedServicePrincipal) !==
      input.expectedServicePrincipal ||
    input.expectedAlgorithm !==
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM ||
    identifier(input.expectedKid) !== input.expectedKid ||
    input.expectedPurpose !==
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE ||
    signer.algorithm !==
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM ||
    signer.issuer !== input.expectedIssuer ||
    signer.audience !== input.expectedAudience ||
    signer.kid !== input.expectedKid ||
    signer.clientId !== input.expectedClientId ||
    signer.servicePrincipal !== input.expectedServicePrincipal ||
    signer.purpose !== input.expectedPurpose
  ) fail();
}

function sha256Hex(domain, source) {
  return hashDigest([
    [domain + "\0", "ascii"],
    [source, "ascii"]
  ], "hex");
}

function inputDigest(source) {
  return INPUT_DIGEST_PREFIX + sha256Hex(INPUT_DIGEST_DOMAIN, source);
}

function tokenId(payloadWithoutTokenIdWire) {
  return sha256Hex(JTI_DOMAIN, payloadWithoutTokenIdWire);
}

function base64urlAscii(value) {
  const bytes = safeApply(safeBufferFrom, safeBuffer, [value, "ascii"]);
  return safeApply(safeBufferToString, bytes, ["base64url"]);
}

function exactSignatureBytes(value) {
  if (value === null || typeof value !== "object" || safeIsProxy(value)) fail();
  const prototype = safeObjectGetPrototypeOf(value);
  if (prototype !== uint8ArrayPrototype && prototype !== bufferPrototype) fail();
  const byteLength = typedArrayLength(value);
  if (byteLength < 256 || byteLength > 1_024) fail();
  const descriptors = safeObjectGetOwnPropertyDescriptors(value);
  const keys = safeReflectOwnKeys(descriptors);
  if (keys.length !== byteLength) fail();
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (
      key !== `${index}` || descriptors[key].enumerable !== true ||
      !safeObjectHasOwn(descriptors[key], "value") ||
      descriptors[key].value !== value[index]
    ) fail();
  }
  return safeApply(safeBufferFrom, safeBuffer, [value]);
}

function payloadWires(value) {
  const prefix =
    `{"acceptanceId":${jsonPrimitive(value.acceptanceId)}` +
    `,"associationId":${jsonPrimitive(value.associationId)}` +
    `,"attemptId":${jsonPrimitive(value.attemptId)}` +
    `,"aud":${jsonPrimitive(value.audience)}` +
    `,"clientId":${jsonPrimitive(value.clientId)}` +
    `,"enrollmentChallengeId":${jsonPrimitive(value.challengeId)}` +
    `,"expiresAt":${jsonPrimitive(value.expiresAt)}` +
    `,"inputDigest":${jsonPrimitive(value.inputDigest)}` +
    `,"iss":${jsonPrimitive(value.issuer)}` +
    `,"issuedAt":${jsonPrimitive(value.issuedAt)}`;
  const suffix =
    `,"purpose":${jsonPrimitive(
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE
    )}` +
    `,"result":${jsonPrimitive(
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_RESULT
    )}` +
    `,"schema":${jsonPrimitive(
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_SCHEMA
    )}` +
    `,"servicePrincipal":${jsonPrimitive(value.servicePrincipal)}` +
    `,"version":${VERSION}}`;
  const withoutTokenId = prefix + suffix;
  const jti = tokenId(withoutTokenId);
  return prefix + `,"jti":${jsonPrimitive(jti)}` + suffix;
}

function protectedHeaderWire(kid) {
  return `{"alg":${jsonPrimitive(
    PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM
  )},"kid":${jsonPrimitive(kid)},"typ":${jsonPrimitive(
    PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_TYPE
  )}}`;
}

/**
 * Construct the dedicated opaque V2 infrastructure signer port. The returned
 * frozen object exposes immutable binding metadata and no signing operation.
 */
export function createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2(
  input = {}
) {
  try {
    const value = ownData(input, SIGNER_FIELDS);
    if (
      value.algorithm !==
        PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM ||
      typeof value.signExact !== "function" || safeIsProxy(value.signExact) ||
      value.purpose !==
        PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE
    ) fail();
    const metadata = safeObjectFreeze({
      algorithm:
        PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
      audience: statementAudience(value.audience),
      clientId: identifier(value.clientId),
      issuer: issuer(value.issuer),
      kid: identifier(value.kid),
      purpose: PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
      servicePrincipal: identifier(value.servicePrincipal)
    });
    const state = safeObjectFreeze({
      algorithm: metadata.algorithm,
      audience: metadata.audience,
      clientId: metadata.clientId,
      issuer: metadata.issuer,
      kid: metadata.kid,
      purpose: metadata.purpose,
      servicePrincipal: metadata.servicePrincipal,
      signExact: value.signExact
    });
    safeApply(safeWeakMapSet, signerStates, [metadata, state]);
    return metadata;
  } catch {
    fail();
  }
}

/**
 * Produce the exact UBID-owned V2 compact JWS only after the real Social
 * BIP340 plus strict Ed25519 verifier authenticates the complete input wire.
 * Deadlines constrain evidence freshness only and grant no live authority.
 */
export async function produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
  input = {},
  options = {
    preacceptedEnrollmentVerificationStatementsV2Enabled:
      PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENTS_V2_ENABLED_DEFAULT
  }
) {
  try {
    requireEnabled(options);
    const value = ownData(input, PRODUCER_FIELDS);
    if (
      typeof value.inputWire !== "string" ||
      typeof value.contextWire !== "string"
    ) fail();

    // Only this exact module-created result can cross the cryptographic gate.
    const verified = await verifyMessagingDevicePreacceptedEnrollmentV2(
      value.inputWire
    );
    const evidence = projectMessagingDevicePreacceptedEnrollmentV2(verified);

    // Reparse the exact authenticated bytes with captured primordials. These
    // are the only values allowed to shape the fixed signing records.
    const verificationInput = closedVerifiedJson(
      value.inputWire,
      INPUT_FIELDS,
      MAX_INPUT_BYTES
    );
    if (verificationInput.context !== value.contextWire) fail();
    const context = closedVerifiedJson(
      value.contextWire,
      CONTEXT_FIELDS,
      MAX_CONTEXT_BYTES
    );
    const enrollment = closedVerifiedJson(
      verificationInput.enrollment,
      ENROLLMENT_FIELDS,
      MAX_ENROLLMENT_BYTES
    );
    const approvalEvent = closedVerifiedJson(
      verificationInput.approvalEvent,
      EVENT_FIELDS,
      MAX_INPUT_BYTES
    );
    const authorization = closedVerifiedJson(
      approvalEvent.content,
      AUTHORIZATION_FIELDS,
      MAX_AUTHORIZATION_BYTES
    );
    const authorizationContext = ownData(
      authorization.context,
      AUTHORIZATION_CONTEXT_FIELDS
    );
    const preEnrollment = closedVerifiedJson(
      authorization.preEnrollment,
      PRE_ENROLLMENT_FIELDS,
      MAX_PRE_ENROLLMENT_BYTES
    );
    const claimContainer = closedVerifiedJson(
      authorization.content,
      CLAIM_CONTAINER_FIELDS,
      MAX_AUTHORIZATION_BYTES
    );
    const binding = ownData(
      claimContainer.authorization,
      LIFECYCLE_FIELDS
    );
    const derivedInputDigest = inputDigest(value.inputWire);
    if (
      evidence.acceptanceId !== verificationInput.acceptanceId ||
      evidence.associationId !== context.associationId ||
      evidence.inputDigest !== derivedInputDigest ||
      evidence.subject !== context.subject ||
      context.challengeId !== enrollment.enrollmentChallengeId ||
      context.audience !== enrollment.audience ||
      context.subject !== enrollment.subject ||
      context.subject !== preEnrollment.subject ||
      context.subject !== binding.subject
    ) fail();

    const signer = signerState(value.signer);
    assertConfigured(value, context, signer);
    const now = integer(value.now);
    const lifetime = integer(value.statementLifetimeMs, true);
    const phoneDeadline = integer(value.phoneSessionExpiresAtMs, true);
    const approverDeadline = integer(
      value.approverSessionExpiresAtMs,
      true
    );
    const fullDeadline = integer(value.fullExpiresAtMs, true);
    const bindingDeadline = integer(value.x25519BindingExpiresAtMs, true);
    const bindingValidFrom = seconds(binding.bindingValidFrom) * 1_000;
    const bindingExpiresAt = seconds(binding.bindingExpiresAt) * 1_000;
    if (
      lifetime >
        MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_LIFETIME_MS ||
      bindingDeadline !== bindingExpiresAt
    ) fail();
    const expiresAt = now + lifetime;
    if (!safeNumberIsSafeInteger(expiresAt)) fail();

    const transcriptStarts = [
      enrollment.issuedAt,
      preEnrollment.issuedAt,
      seconds(authorizationContext.createdAt) * 1_000,
      seconds(binding.issuedAt) * 1_000,
      bindingValidFrom
    ];
    const transcriptDeadlines = [
      enrollment.expiresAt,
      preEnrollment.expiresAt,
      seconds(authorizationContext.expiresAt) * 1_000,
      seconds(binding.expiresAt) * 1_000,
      bindingExpiresAt,
      phoneDeadline,
      approverDeadline,
      fullDeadline,
      bindingDeadline
    ];
    for (let index = 0; index < transcriptStarts.length; index += 1) {
      if (now < transcriptStarts[index]) fail();
    }
    for (let index = 0; index < transcriptDeadlines.length; index += 1) {
      if (
        now >= transcriptDeadlines[index] ||
        expiresAt > transcriptDeadlines[index]
      ) fail();
    }

    const payloadWire = payloadWires({
      acceptanceId: verificationInput.acceptanceId,
      associationId: context.associationId,
      attemptId: context.attemptId,
      audience: value.expectedAudience,
      challengeId: enrollment.enrollmentChallengeId,
      clientId: value.expectedClientId,
      expiresAt,
      inputDigest: derivedInputDigest,
      issuedAt: now,
      issuer: value.expectedIssuer,
      servicePrincipal: value.expectedServicePrincipal
    });
    const headerWire = protectedHeaderWire(signer.kid);
    if (
      safeApply(safeBufferByteLength, safeBuffer, [headerWire, "ascii"]) >
        MAX_PROTECTED_HEADER_BYTES ||
      safeApply(safeBufferByteLength, safeBuffer, [payloadWire, "ascii"]) >
        MAX_PAYLOAD_BYTES
    ) fail();
    const signingInput =
      `${base64urlAscii(headerWire)}.${base64urlAscii(payloadWire)}`;

    let suppliedSignature;
    try {
      suppliedSignature = await safeApply(
        signer.signExact,
        undefined,
        [safeApply(safeBufferFrom, safeBuffer, [signingInput, "ascii"])]
      );
    } catch {
      fail();
    }
    const signature = exactSignatureBytes(suppliedSignature);
    const signatureSegment = safeApply(
      safeBufferToString,
      signature,
      ["base64url"]
    );
    const statement = `${signingInput}.${signatureSegment}`;
    if (
      signatureSegment.length === 0 ||
      safeApply(safeBufferByteLength, safeBuffer, [statement, "ascii"]) >
        MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_BYTES
    ) fail();
    return statement;
  } catch {
    fail();
  }
}
