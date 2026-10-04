// Dormant cryptographic verifier for the merged register + initial V2 input.
// The branded result is evidence only: it grants no acceptance or authority.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  createEnrollmentProofSigningPreimageV2,
  digestEnrollmentV2,
  parseEnrollmentProofV2,
  parseEnrollmentV2,
  strictVerifyMessagingDeviceEd25519V1
} from "./messaging-device-proof-profile-v1.mjs";
import {
  parseMessagingDeviceVerificationContextV1
} from "./messaging-device-verification-statement-v1.mjs";
import {
  acceptanceIdPreimageV2,
  acceptanceIdV2,
  approvalEventIdInputV2,
  approvalEventIdV2,
  authorizationDigestV2,
  createAcceptanceV2,
  parseApprovalEventV2,
  parseAuthorizationEnvelopeV2,
  parsePreEnrollmentV2,
  preEnrollmentDigestV2
} from "../../web/mobile-device-authorization-contract-v2.mjs";

const safeBuffer = Buffer;
const safeCreateHash = createHash;
const safeIsProxy = isProxy;
const safeApply = Reflect.apply;
const SafeArray = Array;
const safeArrayIsArray = SafeArray.isArray;
const SafeArrayBuffer = ArrayBuffer;
const safeBigInt = BigInt;
const SafeDate = Date;
const safeDateParse = SafeDate.parse;
const safeDateToISOString = SafeDate.prototype.toISOString;
const SafeFunction = Function;
const safeGlobalThis = globalThis;
const SafeJSON = JSON;
const safeJsonParse = SafeJSON.parse;
const safeJsonStringify = SafeJSON.stringify;
const SafeMath = Math;
const SafeNumber = Number;
const safeNumberIsFinite = SafeNumber.isFinite;
const safeNumberIsSafeInteger = SafeNumber.isSafeInteger;
const SafeObject = Object;
const safeObjectCreate = SafeObject.create;
const safeObjectDefineProperty = SafeObject.defineProperty;
const safeObjectFreeze = SafeObject.freeze;
const safeObjectGetOwnPropertyDescriptor =
  SafeObject.getOwnPropertyDescriptor;
const safeObjectGetOwnPropertyDescriptors =
  SafeObject.getOwnPropertyDescriptors;
const safeObjectGetPrototypeOf = SafeObject.getPrototypeOf;
const safeObjectHasOwn = SafeObject.hasOwn;
const safeObjectIsFrozen = SafeObject.isFrozen;
const SafeReflect = Reflect;
const safeReflectOwnKeys = SafeReflect.ownKeys;
const SafeRegExp = RegExp;
const safeRegExpExec = SafeRegExp.prototype.exec;
const SafeString = String;
const safeStringCharCodeAt = SafeString.prototype.charCodeAt;
const SafeSymbol = Symbol;
const SafeTextEncoder = TextEncoder;
const safeTextEncoderEncode = SafeTextEncoder.prototype.encode;
const SafeTypeError = TypeError;
const SafeUint8Array = Uint8Array;
const safeWeakSetAdd = WeakSet.prototype.add;
const safeWeakSetHas = WeakSet.prototype.has;
const safeBufferByteLength = safeBuffer.byteLength;
const sha256HashPrototype = Object.getPrototypeOf(safeCreateHash("sha256"));
const safeSha256HashUpdate = sha256HashPrototype.update;
const safeSha256HashDigest = sha256HashPrototype.digest;
const objectPrototype = SafeObject.prototype;
const arrayPrototype = SafeArray.prototype;
const arrayIteratorPrototype = safeObjectGetPrototypeOf(
  [][SafeSymbol.iterator]()
);
const arrayBufferPrototype = SafeArrayBuffer.prototype;
const bufferPrototype = safeBuffer.prototype;
const uint8ArrayPrototype = SafeUint8Array.prototype;
const typedArrayConstructor = safeObjectGetPrototypeOf(SafeUint8Array);
const typedArrayPrototype = safeObjectGetPrototypeOf(uint8ArrayPrototype);
const safeTypedArrayLength = safeObjectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  "length"
).get;

export const PREACCEPTED_ENROLLMENT_V2_RUNTIME_ENABLED = false;
export const PREACCEPTED_ENROLLMENT_V2_SCHEMA =
  "hodlxxi.social_preaccepted_enrollment_verification_input.v2";
export const PREACCEPTED_ENROLLMENT_V2_ASSOCIATION_LINK_SCHEMA =
  "hodlxxi.social_pre_enrollment_association_link.v2";

const INPUT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2";
const INPUT_DIGEST_PREFIX =
  "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:";
const ASSOCIATION_CREATION_SCHEMA =
  "hodlxxi.social_messaging_device_ed25519_association_creation.v1";
const ASSOCIATION_ID_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1";
const ACCEPTANCE_ID_DOMAIN =
  "HODLXXI_SOCIAL_MOBILE_PRE_ENROLLMENT_ACCEPTANCE_ID_V2";
const ENROLLMENT_PROOF_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2";
const ENROLLMENT_PROOF_PREIMAGE_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2";
const DEVICE_PROOF_PROFILE =
  "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1";
const MAX_INPUT_BYTES = 24_576;
const MAX_EVENT_BYTES = 24_576;
const MAX_AUTHORIZATION_BYTES = 16_384;
const MAX_PRE_ENROLLMENT_BYTES = 8_192;
const MAX_CONTEXT_BYTES = 4_096;
const MAX_ENROLLMENT_BYTES = 4_096;
const MAX_PROOF_BYTES = 1_024;
const INPUT_FIELDS = [
  "acceptanceId", "approvalEvent", "context", "enrollment", "phoneProof",
  "schema", "version"
];
const EVENT_FIELDS = [
  "content", "created_at", "id", "kind", "pubkey", "sig", "tags"
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
const ENROLLMENT_PROOF_FIELDS = [
  "algorithm", "enrollmentChallengeId", "enrollmentDigest", "profile",
  "publicKey", "schema", "signature", "version"
];
const PARSED_PRE_ENROLLMENT_FIELDS = [
  "bindingAuthorizationDigest", "deviceId", "ed25519PublicKey", "expiresAt",
  "issuedAt", "pairingId", "requestId", "subject", "wire",
  "x25519BindingId", "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const PARSED_CONTEXT_FIELDS = [
  "approverFullProofId", "approverSessionBinding", "associationId",
  "associationVersion", "attemptId", "audience", "authorityEpoch",
  "bindingId", "bindingVersion", "challengeId", "challengeKind", "deviceId",
  "ed25519PublicKey", "fullProofId", "predecessorAssociationId", "profile",
  "sessionBinding", "subject", "wire", "x25519PublicKeyCommitment"
];
const APPROVAL_TAG_NAMES = [
  "purpose", "authorization-digest", "pre-enrollment-digest", "request-id",
  "action", "pairing-id"
];
const HEX64 = /^[0-9a-f]{64}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const PRE_ENROLLMENT_SCHEMA =
  "hodlxxi.social_messaging_device_pre_enrollment.v2";
const PRE_ENROLLMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_V2";
const AUTHORIZATION_SCHEMA =
  "hodlxxi.social_messaging_device_authorization_method.v2";
const AUTHORIZATION_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V2";
const AUTHORIZATION_METHOD = "qr_desktop_pre_enrollment_v2";
const APPROVAL_EVENT_PURPOSE =
  "hodlxxi-social-messaging-device-qr-pre-enrollment-approval-v2";
const LIFECYCLE_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1";
const LIFECYCLE_SCHEMA =
  "hodlxxi.social_messaging_device_binding_authorization.v1";
const BINDING_SCHEMA =
  "hodlxxi.social_messaging_device_binding_record.v1";
const PRE_ENROLLMENT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_DIGEST_V2";
const PRE_ENROLLMENT_DIGEST_PREFIX =
  "hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:";
const X25519_COMMITMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1";
const ACCEPTANCE_ID_PREIMAGE_SCHEMA =
  "hodlxxi.social_mobile_pre_enrollment_acceptance_id_preimage.v2";
const ACCEPTANCE_SCHEMA =
  "hodlxxi.social_mobile_authorization_acceptance.v2";
const MAX_PRE_ENROLLMENT_LIFETIME_MS = 600_000;
const MAX_PAIRING_LIFETIME_SECONDS = 300;
const verifiedResults = new WeakSet();
const encoder = new SafeTextEncoder();

function descriptor(target, key) {
  return [target, key, safeObjectGetOwnPropertyDescriptor(target, key)];
}

// Security boundary: all caller/network bytes and public evidence are
// untrusted. The Node process/executable, Node/OpenSSL built-ins, trusted
// deployment source, package-lock-selected dependencies, and intentionally
// loaded application code are trusted. Arbitrary JavaScript rewriting
// process-wide state is process compromise; isolation would require a future
// process boundary. The imported V1/V2 parsers use live primordials, so these
// selected descriptor observations remain non-exhaustive, non-normative
// defense in depth only. They are not a complete mutable-primordial inventory.
// The independent exact-wire BIP340 check below remains mandatory.
const verificationDescriptors = [
  descriptor(safeGlobalThis, "Array"),
  descriptor(safeGlobalThis, "ArrayBuffer"),
  descriptor(safeGlobalThis, "BigInt"),
  descriptor(safeGlobalThis, "Boolean"),
  descriptor(safeGlobalThis, "Date"),
  descriptor(safeGlobalThis, "Function"),
  descriptor(safeGlobalThis, "JSON"),
  descriptor(safeGlobalThis, "Math"),
  descriptor(safeGlobalThis, "Number"),
  descriptor(safeGlobalThis, "Object"),
  descriptor(safeGlobalThis, "Reflect"),
  descriptor(safeGlobalThis, "RegExp"),
  descriptor(safeGlobalThis, "String"),
  descriptor(safeGlobalThis, "Symbol"),
  descriptor(safeGlobalThis, "TextEncoder"),
  descriptor(safeGlobalThis, "TypeError"),
  descriptor(safeGlobalThis, "Uint8Array"),
  descriptor(SafeArray, "from"),
  descriptor(SafeArray, "isArray"),
  descriptor(SafeArray, SafeSymbol.species),
  descriptor(arrayPrototype, "constructor"),
  descriptor(arrayPrototype, SafeSymbol.iterator),
  descriptor(arrayIteratorPrototype, "next"),
  descriptor(arrayPrototype, "then"),
  descriptor(arrayPrototype, "toJSON"),
  descriptor(arrayPrototype, "every"),
  descriptor(arrayPrototype, "filter"),
  descriptor(arrayPrototype, "forEach"),
  descriptor(arrayPrototype, "includes"),
  descriptor(arrayPrototype, "join"),
  descriptor(arrayPrototype, "map"),
  descriptor(arrayPrototype, "push"),
  descriptor(arrayPrototype, "reduce"),
  descriptor(arrayPrototype, "slice"),
  descriptor(arrayPrototype, "some"),
  descriptor(arrayPrototype, "sort"),
  descriptor(SafeArrayBuffer, "isView"),
  descriptor(arrayBufferPrototype, "slice"),
  descriptor(arrayBufferPrototype, "then"),
  descriptor(arrayBufferPrototype, "toJSON"),
  descriptor(SafeDate, "parse"),
  descriptor(SafeDate.prototype, "toISOString"),
  descriptor(SafeFunction.prototype, "call"),
  descriptor(SafeFunction.prototype, SafeSymbol.hasInstance),
  descriptor(SafeJSON, "parse"),
  descriptor(SafeJSON, "stringify"),
  descriptor(SafeMath, "abs"),
  descriptor(SafeMath, "floor"),
  descriptor(SafeNumber, "isFinite"),
  descriptor(SafeNumber, "isInteger"),
  descriptor(SafeNumber, "isSafeInteger"),
  descriptor(SafeNumber, "parseInt"),
  descriptor(SafeNumber.prototype, "toString"),
  descriptor(SafeObject, "create"),
  descriptor(SafeObject, "defineProperty"),
  descriptor(SafeObject, "entries"),
  descriptor(SafeObject, "freeze"),
  descriptor(SafeObject, "fromEntries"),
  descriptor(SafeObject, "getOwnPropertyDescriptor"),
  descriptor(SafeObject, "getOwnPropertyDescriptors"),
  descriptor(SafeObject, "getPrototypeOf"),
  descriptor(SafeObject, "hasOwn"),
  descriptor(SafeObject, "isFrozen"),
  descriptor(SafeObject, "keys"),
  descriptor(SafeObject, "values"),
  descriptor(objectPrototype, "then"),
  descriptor(objectPrototype, "toJSON"),
  descriptor(SafeReflect, "ownKeys"),
  descriptor(SafeRegExp.prototype, "exec"),
  descriptor(SafeRegExp.prototype, "test"),
  descriptor(SafeString, "fromCharCode"),
  descriptor(SafeString.prototype, SafeSymbol.iterator),
  descriptor(SafeString.prototype, "charCodeAt"),
  descriptor(SafeString.prototype, "endsWith"),
  descriptor(SafeString.prototype, "match"),
  descriptor(SafeString.prototype, "padStart"),
  descriptor(SafeString.prototype, "replace"),
  descriptor(SafeString.prototype, "repeat"),
  descriptor(SafeString.prototype, "slice"),
  descriptor(SafeString.prototype, "split"),
  descriptor(SafeString.prototype, "startsWith"),
  descriptor(SafeTextEncoder.prototype, "encode"),
  descriptor(SafeUint8Array, "from"),
  descriptor(SafeUint8Array, "of"),
  descriptor(SafeUint8Array, SafeSymbol.species),
  descriptor(uint8ArrayPrototype, "constructor"),
  descriptor(uint8ArrayPrototype, SafeSymbol.iterator),
  descriptor(uint8ArrayPrototype, "then"),
  descriptor(uint8ArrayPrototype, "toJSON"),
  descriptor(typedArrayConstructor, "from"),
  descriptor(typedArrayConstructor, "of"),
  descriptor(typedArrayConstructor, SafeSymbol.species),
  descriptor(typedArrayPrototype, "buffer"),
  descriptor(typedArrayPrototype, "byteLength"),
  descriptor(typedArrayPrototype, "byteOffset"),
  descriptor(typedArrayPrototype, "constructor"),
  descriptor(typedArrayPrototype, SafeSymbol.iterator),
  descriptor(typedArrayPrototype, "then"),
  descriptor(typedArrayPrototype, "toJSON"),
  descriptor(typedArrayPrototype, "length"),
  descriptor(typedArrayPrototype, "set"),
  descriptor(typedArrayPrototype, "slice"),
  descriptor(safeBuffer, "prototype"),
  descriptor(bufferPrototype, "buffer"),
  descriptor(bufferPrototype, "then"),
  descriptor(bufferPrototype, "toJSON")
];

function sameDescriptor(target, key, expected) {
  const actual = safeObjectGetOwnPropertyDescriptor(target, key);
  if (actual === undefined || expected === undefined) {
    return actual === expected;
  }
  return actual.configurable === expected.configurable &&
    actual.enumerable === expected.enumerable &&
    actual.get === expected.get && actual.set === expected.set &&
    actual.value === expected.value && actual.writable === expected.writable;
}

function verificationPrimordialsIntact() {
  for (let index = 0; index < verificationDescriptors.length; index += 1) {
    const entry = verificationDescriptors[index];
    if (!sameDescriptor(entry[0], entry[1], entry[2])) return false;
  }
  return true;
}

const deny = () => {
  throw new SafeTypeError(
    "messaging device preaccepted enrollment v2 unavailable"
  );
};
function sha256Digest(parts, outputEncoding) {
  const hash = safeCreateHash("sha256");
  for (let index = 0; index < parts.length; index += 1) {
    safeApply(safeSha256HashUpdate, hash, [
      parts[index][0],
      parts[index][1]
    ]);
  }
  return outputEncoding === undefined
    ? safeApply(safeSha256HashDigest, hash, [])
    : safeApply(safeSha256HashDigest, hash, [outputEncoding]);
}

function typedArrayLength(value) {
  return safeApply(safeTypedArrayLength, value, []);
}

function exactUint8Array(value) {
  return value !== null && typeof value === "object" &&
    !safeIsProxy(value) &&
    safeObjectGetPrototypeOf(value) === uint8ArrayPrototype;
}

function digestArrayBuffer(bytes) {
  const length = typedArrayLength(bytes);
  const result = new SafeArrayBuffer(length);
  const view = new SafeUint8Array(result);
  for (let index = 0; index < length; index += 1) {
    view[index] = bytes[index];
  }
  return result;
}

const trustedCrypto = safeObjectFreeze({
  subtle: safeObjectFreeze({
    async digest(algorithm, value) {
      if (
        algorithm !== "SHA-256" || !exactUint8Array(value) ||
        !verificationPrimordialsIntact()
      ) deny();
      const bytes = sha256Digest([[value, undefined]]);
      const result = digestArrayBuffer(bytes);
      safeObjectDefineProperty(result, "then", {
        configurable: false,
        enumerable: false,
        value: undefined,
        writable: false
      });
      if (!verificationPrimordialsIntact()) deny();
      return result;
    }
  })
});

function regexpMatches(pattern, value) {
  return safeApply(safeRegExpExec, pattern, [value]) !== null;
}

function jsonPrimitive(value) {
  const encoded = safeApply(safeJsonStringify, undefined, [value]);
  if (typeof encoded !== "string") deny();
  return encoded;
}

function canonical(value) {
  if (
    value === null || typeof value === "string" ||
    typeof value === "boolean"
  ) return jsonPrimitive(value);
  if (typeof value === "number") {
    if (!safeNumberIsFinite(value)) deny();
    return jsonPrimitive(value);
  }
  if (typeof value !== "object" || safeIsProxy(value)) deny();
  const descriptors = safeObjectGetOwnPropertyDescriptors(value);
  if (safeArrayIsArray(value)) {
    if (safeObjectGetPrototypeOf(value) !== arrayPrototype) deny();
    const length = value.length;
    const keys = safeReflectOwnKeys(descriptors);
    if (keys.length !== length + 1 || descriptors.length?.value !== length) {
      deny();
    }
    let wire = "[";
    for (let index = 0; index < length; index += 1) {
      const item = descriptors[`${index}`];
      if (
        item === undefined || item.enumerable !== true ||
        !safeObjectHasOwn(item, "value")
      ) deny();
      if (index !== 0) wire += ",";
      wire += canonical(item.value);
    }
    return wire + "]";
  }
  const prototype = safeObjectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) deny();
  const keys = safeReflectOwnKeys(descriptors);
  const sorted = safeObjectCreate(null);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (
      typeof key !== "string" || descriptors[key].enumerable !== true ||
      !safeObjectHasOwn(descriptors[key], "value")
    ) deny();
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
    wire += `${jsonPrimitive(key)}:${canonical(descriptors[key].value)}`;
  }
  return wire + "}";
}

function fieldAllowed(fields, candidate) {
  for (let index = 0; index < fields.length; index += 1) {
    if (fields[index] === candidate) return true;
  }
  return false;
}

function exactData(value, fields) {
  if (
    value === null || typeof value !== "object" || safeArrayIsArray(value) ||
    safeIsProxy(value) || safeObjectGetPrototypeOf(value) !== objectPrototype
  ) deny();
  const descriptors = safeObjectGetOwnPropertyDescriptors(value);
  const keys = safeReflectOwnKeys(descriptors);
  if (keys.length !== fields.length) deny();
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (
      typeof key !== "string" || !fieldAllowed(fields, key) ||
      descriptors[key].enumerable !== true ||
      !safeObjectHasOwn(descriptors[key], "value")
    ) deny();
  }
  const result = safeObjectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (!safeObjectHasOwn(descriptors, field)) deny();
    result[field] = descriptors[field].value;
  }
  return result;
}

function samePrimitiveFields(actual, expected, fields, expectedWire) {
  const value = exactData(actual, fields);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const expectedValue = field === "wire" ? expectedWire : expected[field];
    if (value[field] !== expectedValue) deny();
  }
  return value;
}

function closedAuthorizationContext(value) {
  const context = exactData(value, AUTHORIZATION_CONTEXT_FIELDS);
  for (let index = 0; index < AUTHORIZATION_CONTEXT_FIELDS.length; index += 1) {
    if (typeof context[AUTHORIZATION_CONTEXT_FIELDS[index]] !== "string") deny();
  }
}

function closedApprovalTags(value) {
  if (
    !safeArrayIsArray(value) ||
    safeObjectGetPrototypeOf(value) !== arrayPrototype ||
    value.length !== APPROVAL_TAG_NAMES.length
  ) deny();
  for (let index = 0; index < APPROVAL_TAG_NAMES.length; index += 1) {
    const tag = value[index];
    if (
      !safeArrayIsArray(tag) ||
      safeObjectGetPrototypeOf(tag) !== arrayPrototype || tag.length !== 2 ||
      tag[0] !== APPROVAL_TAG_NAMES[index] ||
      typeof tag[1] !== "string" || tag[1].length === 0 ||
      tag[1].length > 128 || regexpMatches(/[^\x20-\x7e]/, tag[1])
    ) deny();
  }
}

function closedJson(source, fields, maximum, validateNested) {
  if (
    typeof source !== "string" || source.length === 0 ||
    source.length > maximum || regexpMatches(/[^\x20-\x7e]/, source) ||
    safeApply(safeBufferByteLength, safeBuffer, [source, "utf8"]) > maximum
  ) deny();
  let parsed;
  try { parsed = safeApply(safeJsonParse, undefined, [source]); } catch { deny(); }
  const value = exactData(parsed, fields);
  validateNested?.(value);
  if (canonical(value) !== source) deny();
  return safeObjectFreeze(value);
}

function utcSecond(value) {
  if (typeof value !== "string" || !regexpMatches(ISO_SECOND, value)) deny();
  const milliseconds = safeApply(safeDateParse, SafeDate, [value]);
  if (!safeNumberIsSafeInteger(milliseconds)) deny();
  if (
    safeApply(safeDateToISOString, new SafeDate(milliseconds), []) !==
      value.slice(0, -1) + ".000Z"
  ) deny();
  return milliseconds / 1_000;
}

function localAuthorizationEvidence(value) {
  const {
    authorization,
    authorizationContext,
    authorizationWire,
    claimContainer,
    event,
    lifecycle,
    preEnrollment,
    preEnrollmentWire
  } = value;
  const lifecycleIssuedAt = utcSecond(lifecycle.issuedAt);
  const lifecycleExpiresAt = utcSecond(lifecycle.expiresAt);
  const bindingValidFrom = utcSecond(lifecycle.bindingValidFrom);
  const bindingExpiresAt = utcSecond(lifecycle.bindingExpiresAt);
  const contextCreatedAt = utcSecond(authorizationContext.createdAt);
  const contextExpiresAt = utcSecond(authorizationContext.expiresAt);
  if (
    authorization.schema !== AUTHORIZATION_SCHEMA ||
    authorization.version !== 2 ||
    authorization.domain !== AUTHORIZATION_DOMAIN ||
    authorization.method !== AUTHORIZATION_METHOD ||
    claimContainer.domain !== LIFECYCLE_DOMAIN ||
    lifecycle.schema !== LIFECYCLE_SCHEMA || lifecycle.version !== 1 ||
    lifecycle.bindingRecordSchema !== BINDING_SCHEMA ||
    lifecycle.bindingRecordVersion !== 1 ||
    lifecycle.algorithm !== "x25519-v1" ||
    lifecycle.operation !== "register" || lifecycle.bindingVersion !== 1 ||
    lifecycle.priorBindingId !== null ||
    !regexpMatches(HEX64, lifecycle.subject) ||
    !regexpMatches(HEX64, lifecycle.deviceId) ||
    !regexpMatches(HEX64, lifecycle.publicKey) ||
    lifecycle.publicKey === lifecycle.subject ||
    !regexpMatches(HEX64, lifecycle.requestId) ||
    bindingValidFrom !== lifecycleIssuedAt ||
    lifecycleIssuedAt >= lifecycleExpiresAt ||
    lifecycleExpiresAt > bindingExpiresAt ||
    contextCreatedAt >= contextExpiresAt ||
    contextExpiresAt > contextCreatedAt + MAX_PAIRING_LIFETIME_SECONDS
  ) deny();
  if (
    !regexpMatches(HEX64, authorizationContext.desktopContext) ||
    !regexpMatches(HEX64, authorizationContext.exchangeCommitment) ||
    !regexpMatches(HEX64, authorizationContext.pairingId) ||
    !regexpMatches(HEX64, authorizationContext.secretCommitment)
  ) deny();
  if (
    preEnrollment.schema !== PRE_ENROLLMENT_SCHEMA ||
    preEnrollment.version !== 2 ||
    preEnrollment.domain !== PRE_ENROLLMENT_DOMAIN ||
    preEnrollment.profile !== DEVICE_PROOF_PROFILE ||
    !regexpMatches(HEX64, preEnrollment.bindingAuthorizationDigest) ||
    !regexpMatches(HEX64, preEnrollment.deviceId) ||
    !regexpMatches(HEX64, preEnrollment.ed25519PublicKey) ||
    !regexpMatches(HEX64, preEnrollment.pairingId) ||
    !regexpMatches(HEX64, preEnrollment.requestId) ||
    !regexpMatches(HEX64, preEnrollment.subject) ||
    !regexpMatches(HEX64, preEnrollment.x25519BindingId) ||
    !regexpMatches(X25519_COMMITMENT, preEnrollment.x25519PublicKeyCommitment) ||
    !safeNumberIsSafeInteger(preEnrollment.issuedAt) ||
    !safeNumberIsSafeInteger(preEnrollment.expiresAt) ||
    preEnrollment.issuedAt < 0 ||
    preEnrollment.expiresAt <= preEnrollment.issuedAt ||
    preEnrollment.expiresAt - preEnrollment.issuedAt >
      MAX_PRE_ENROLLMENT_LIFETIME_MS ||
    preEnrollment.x25519BindingVersion !== 1 ||
    preEnrollment.transitionKind !== "initial" ||
    preEnrollment.preEffectAssociationState !== "absent" ||
    preEnrollment.preEffectAssociationId !== null ||
    preEnrollment.preEffectAssociationVersion !== null ||
    preEnrollment.preEffectAuthorityEpoch !== 0 ||
    preEnrollment.proposedAssociationVersion !== 1 ||
    preEnrollment.proposedAuthorityEpoch !== 1 ||
    preEnrollment.proposedPredecessorAssociationId !== null
  ) deny();
  const bindingWire = canonical({
    algorithm: lifecycle.algorithm,
    bindingVersion: lifecycle.bindingVersion,
    deviceId: lifecycle.deviceId,
    expiresAt: lifecycle.bindingExpiresAt,
    operation: lifecycle.operation,
    priorBindingId: lifecycle.priorBindingId,
    publicKey: lifecycle.publicKey,
    requestId: lifecycle.requestId,
    schema: lifecycle.bindingRecordSchema,
    subject: lifecycle.subject,
    validFrom: lifecycle.bindingValidFrom,
    version: lifecycle.bindingRecordVersion
  });
  const bindingId = sha256(bindingWire);
  const authorizationDigest = sha256(authorizationWire);
  const preEnrollmentDigest = PRE_ENROLLMENT_DIGEST_PREFIX + domainDigest(
    PRE_ENROLLMENT_DIGEST_DOMAIN,
    preEnrollmentWire
  );
  const x25519Commitment =
    "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + domainDigest(
      X25519_COMMITMENT_DOMAIN,
      lifecycle.publicKey
    );
  if (
    preEnrollment.bindingAuthorizationDigest !== sha256(authorization.content) ||
    preEnrollment.subject !== lifecycle.subject ||
    preEnrollment.deviceId !== lifecycle.deviceId ||
    preEnrollment.requestId !== lifecycle.requestId ||
    preEnrollment.x25519BindingId !== bindingId ||
    preEnrollment.x25519PublicKeyCommitment !== x25519Commitment ||
    preEnrollment.ed25519PublicKey === lifecycle.publicKey ||
    preEnrollment.issuedAt !== lifecycleIssuedAt * 1_000 ||
    preEnrollment.expiresAt > bindingExpiresAt * 1_000 ||
    authorizationContext.pairingId !== preEnrollment.pairingId ||
    contextCreatedAt > lifecycleIssuedAt ||
    lifecycleExpiresAt > contextExpiresAt ||
    event.content !== authorizationWire ||
    event.created_at !== lifecycleIssuedAt || event.kind !== 27236 ||
    event.pubkey !== lifecycle.subject ||
    event.tags[0][1] !== APPROVAL_EVENT_PURPOSE ||
    event.tags[1][1] !== authorizationDigest ||
    event.tags[2][1] !== preEnrollmentDigest ||
    event.tags[3][1] !== preEnrollment.requestId ||
    event.tags[4][1] !== "register" ||
    event.tags[5][1] !== preEnrollment.pairingId
  ) deny();
  const approvalEventIdInput = canonical([
    0,
    lifecycle.subject,
    lifecycleIssuedAt,
    27236,
    event.tags,
    authorizationWire
  ]);
  const approvalEventId = sha256(approvalEventIdInput);
  const acceptanceIdPreimage = canonical({
    approvalEventId,
    authorizationDigest,
    bindingId,
    pairingId: preEnrollment.pairingId,
    preEnrollmentDigest,
    requestId: preEnrollment.requestId,
    schema: ACCEPTANCE_ID_PREIMAGE_SCHEMA,
    subject: preEnrollment.subject,
    version: 2
  });
  const acceptanceId = domainDigest(
    ACCEPTANCE_ID_DOMAIN,
    acceptanceIdPreimage
  );
  const acceptanceWire = canonical({
    acceptanceId,
    approvalEventId,
    authorizationDigest,
    bindingId,
    deviceId: preEnrollment.deviceId,
    ed25519PublicKey: preEnrollment.ed25519PublicKey,
    pairingId: preEnrollment.pairingId,
    preEnrollmentDigest,
    profile: DEVICE_PROOF_PROFILE,
    requestId: preEnrollment.requestId,
    schema: ACCEPTANCE_SCHEMA,
    subject: preEnrollment.subject,
    version: 2,
    x25519BindingVersion: preEnrollment.x25519BindingVersion,
    x25519PublicKeyCommitment: preEnrollment.x25519PublicKeyCommitment
  });
  return safeObjectFreeze({
    acceptanceId,
    acceptanceIdPreimage,
    acceptanceWire,
    approvalEventId,
    approvalEventIdInput,
    authorizationDigest,
    bindingId,
    preEnrollmentDigest
  });
}

const boundedString = (value, maximum) => {
  if (
    typeof value !== "string" || value.length === 0 ||
    value.length > maximum || regexpMatches(/[^\x20-\x7e]/, value) ||
    safeApply(safeBufferByteLength, safeBuffer, [value, "utf8"]) > maximum
  ) deny();
  return value;
};

const sha256 = (source) => sha256Digest([[source, "ascii"]], "hex");
const domainDigest = (domain, source) => sha256Digest([
  [domain + "\0", "ascii"],
  [source, "ascii"]
], "hex");

const BIP340_FIELD_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const BIP340_CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const BIP340_GENERATOR = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
const BIP340_INFINITY = { x: 0n, y: 1n, z: 0n };

function exactHexBytes(value, length) {
  if (typeof value !== "string" || value.length !== length * 2) return null;
  const result = new SafeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    const highCode = safeApply(safeStringCharCodeAt, value, [index * 2]);
    const lowCode = safeApply(safeStringCharCodeAt, value, [index * 2 + 1]);
    const high = highCode >= 48 && highCode <= 57
      ? highCode - 48
      : highCode >= 97 && highCode <= 102 ? highCode - 87 : -1;
    const low = lowCode >= 48 && lowCode <= 57
      ? lowCode - 48
      : lowCode >= 97 && lowCode <= 102 ? lowCode - 87 : -1;
    if (high < 0 || low < 0) return null;
    result[index] = high * 16 + low;
  }
  return result;
}

function bigEndianInteger(bytes, length) {
  let result = 0n;
  for (let index = 0; index < length; index += 1) {
    result = (result << 8n) | safeBigInt(bytes[index]);
  }
  return result;
}

function bip340Mod(value, modulus = BIP340_FIELD_P) {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

function bip340Pow(base, exponent, modulus = BIP340_FIELD_P) {
  let result = 1n;
  let factor = bip340Mod(base, modulus);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = bip340Mod(result * factor, modulus);
    factor = bip340Mod(factor * factor, modulus);
    power >>= 1n;
  }
  return result;
}

function bip340LiftX(x) {
  if (x >= BIP340_FIELD_P) return null;
  const curveY = bip340Mod(x * x * x + 7n);
  let y = bip340Pow(curveY, (BIP340_FIELD_P + 1n) >> 2n);
  if (bip340Mod(y * y) !== curveY) return null;
  if (y & 1n) y = BIP340_FIELD_P - y;
  return { x, y };
}

const bip340Infinity = (point) => point.z === 0n;
const bip340Jacobian = (point) => ({ x: point.x, y: point.y, z: 1n });

function bip340Double(point) {
  if (bip340Infinity(point) || point.y === 0n) return BIP340_INFINITY;
  const xx = bip340Mod(point.x * point.x);
  const yy = bip340Mod(point.y * point.y);
  const yyyy = bip340Mod(yy * yy);
  const s = bip340Mod(
    2n * (bip340Mod((point.x + yy) * (point.x + yy)) - xx - yyyy)
  );
  const m = bip340Mod(3n * xx);
  return {
    x: bip340Mod(m * m - 2n * s),
    y: bip340Mod(m * (s - bip340Mod(m * m - 2n * s)) - 8n * yyyy),
    z: bip340Mod(2n * point.y * point.z)
  };
}

function bip340Add(left, right) {
  if (bip340Infinity(left)) return right;
  if (bip340Infinity(right)) return left;
  const z1z1 = bip340Mod(left.z * left.z);
  const z2z2 = bip340Mod(right.z * right.z);
  const u1 = bip340Mod(left.x * z2z2);
  const u2 = bip340Mod(right.x * z1z1);
  const s1 = bip340Mod(left.y * right.z * z2z2);
  const s2 = bip340Mod(right.y * left.z * z1z1);
  if (u1 === u2) return s1 === s2 ? bip340Double(left) : BIP340_INFINITY;
  const h = bip340Mod(u2 - u1);
  const i = bip340Mod(4n * h * h);
  const j = bip340Mod(h * i);
  const r = bip340Mod(2n * (s2 - s1));
  const v = bip340Mod(u1 * i);
  return {
    x: bip340Mod(r * r - j - 2n * v),
    y: bip340Mod(r * (v - bip340Mod(r * r - j - 2n * v)) - 2n * s1 * j),
    z: bip340Mod(
      (bip340Mod((left.z + right.z) * (left.z + right.z)) - z1z1 - z2z2) * h
    )
  };
}

function bip340Multiply(scalar, point) {
  let result = BIP340_INFINITY;
  let addend = bip340Jacobian(point);
  let value = scalar;
  while (value > 0n) {
    if (value & 1n) result = bip340Add(result, addend);
    addend = bip340Double(addend);
    value >>= 1n;
  }
  return result;
}

function bip340Affine(point) {
  if (bip340Infinity(point)) return null;
  const inverse = bip340Pow(point.z, BIP340_FIELD_P - 2n);
  const squared = bip340Mod(inverse * inverse);
  return {
    x: bip340Mod(point.x * squared),
    y: bip340Mod(point.y * squared * inverse)
  };
}

function strictVerifyBip340Exact(publicKeyHex, messageHex, signatureHex) {
  const publicKeyBytes = exactHexBytes(publicKeyHex, 32);
  const messageBytes = exactHexBytes(messageHex, 32);
  const signatureBytes = exactHexBytes(signatureHex, 64);
  if (
    publicKeyBytes === null || messageBytes === null ||
    signatureBytes === null
  ) return false;
  const publicKey = bip340LiftX(bigEndianInteger(publicKeyBytes, 32));
  const rBytes = new SafeUint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    rBytes[index] = signatureBytes[index];
  }
  const r = bigEndianInteger(rBytes, 32);
  let s = 0n;
  for (let index = 32; index < 64; index += 1) {
    s = (s << 8n) | safeBigInt(signatureBytes[index]);
  }
  if (publicKey === null || r >= BIP340_FIELD_P || s >= BIP340_CURVE_N) {
    return false;
  }
  const tagHash = sha256Digest([["BIP0340/challenge", "ascii"]]);
  const challengeInput = new SafeUint8Array(160);
  for (let index = 0; index < 32; index += 1) {
    challengeInput[index] = tagHash[index];
    challengeInput[32 + index] = tagHash[index];
    challengeInput[64 + index] = rBytes[index];
    challengeInput[96 + index] = publicKeyBytes[index];
    challengeInput[128 + index] = messageBytes[index];
  }
  const challengeDigest = sha256Digest([[challengeInput, undefined]]);
  const challenge = bigEndianInteger(challengeDigest, 32) % BIP340_CURVE_N;
  const negativeChallenge = challenge === 0n
    ? 0n : BIP340_CURVE_N - challenge;
  const candidate = bip340Add(
    bip340Multiply(s, BIP340_GENERATOR),
    bip340Multiply(negativeChallenge, publicKey)
  );
  const point = bip340Affine(candidate);
  return point !== null && !(point.y & 1n) && point.x === r;
}

function exactNostrEventId(event) {
  return sha256(canonical([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]));
}

function preflight(source) {
  const input = closedJson(source, INPUT_FIELDS, MAX_INPUT_BYTES);
  if (
    input.schema !== PREACCEPTED_ENROLLMENT_V2_SCHEMA ||
    input.version !== 2 || typeof input.acceptanceId !== "string" ||
    !regexpMatches(HEX64, input.acceptanceId)
  ) deny();
  const approvalEventWire = boundedString(input.approvalEvent, MAX_EVENT_BYTES);
  const contextWire = boundedString(input.context, MAX_CONTEXT_BYTES);
  const enrollmentWire = boundedString(input.enrollment, MAX_ENROLLMENT_BYTES);
  const phoneProofWire = boundedString(input.phoneProof, MAX_PROOF_BYTES);
  const event = closedJson(
    approvalEventWire,
    EVENT_FIELDS,
    MAX_EVENT_BYTES,
    (value) => closedApprovalTags(value.tags)
  );
  const authorizationWire = boundedString(event.content, MAX_AUTHORIZATION_BYTES);
  const authorization = closedJson(
    authorizationWire,
    AUTHORIZATION_FIELDS,
    MAX_AUTHORIZATION_BYTES,
    (value) => closedAuthorizationContext(value.context)
  );
  const preEnrollmentWire = boundedString(
    authorization.preEnrollment,
    MAX_PRE_ENROLLMENT_BYTES
  );
  // These parsers are all structural and bounded. Both expensive signature
  // checks are deliberately deferred until every nested wire has passed.
  const preEnrollment = closedJson(
    preEnrollmentWire,
    PRE_ENROLLMENT_FIELDS,
    MAX_PRE_ENROLLMENT_BYTES
  );
  const context = closedJson(contextWire, CONTEXT_FIELDS, MAX_CONTEXT_BYTES);
  const enrollment = closedJson(
    enrollmentWire,
    ENROLLMENT_FIELDS,
    MAX_ENROLLMENT_BYTES
  );
  const phoneProof = closedJson(
    phoneProofWire,
    ENROLLMENT_PROOF_FIELDS,
    MAX_PROOF_BYTES
  );
  const claimContainerWire = boundedString(
    authorization.content,
    MAX_AUTHORIZATION_BYTES
  );
  const claimContainer = closedJson(
    claimContainerWire,
    CLAIM_CONTAINER_FIELDS,
    MAX_AUTHORIZATION_BYTES
  );
  const lifecycle = exactData(
    claimContainer.authorization,
    LIFECYCLE_FIELDS
  );
  const authorizationContext = exactData(
    authorization.context,
    AUTHORIZATION_CONTEXT_FIELDS
  );
  samePrimitiveFields(
    parsePreEnrollmentV2(preEnrollmentWire),
    preEnrollment,
    PARSED_PRE_ENROLLMENT_FIELDS,
    preEnrollmentWire
  );
  samePrimitiveFields(
    parseMessagingDeviceVerificationContextV1(contextWire),
    context,
    PARSED_CONTEXT_FIELDS,
    contextWire
  );
  samePrimitiveFields(
    parseEnrollmentV2(enrollmentWire),
    enrollment,
    ENROLLMENT_FIELDS
  );
  samePrimitiveFields(
    parseEnrollmentProofV2(phoneProofWire),
    phoneProof,
    ENROLLMENT_PROOF_FIELDS
  );
  return safeObjectFreeze({
    wire: source,
    acceptanceId: input.acceptanceId,
    approvalEventWire,
    event,
    authorizationWire,
    authorization,
    authorizationContext,
    claimContainer,
    lifecycle,
    preEnrollmentWire,
    preEnrollment,
    contextWire,
    context,
    enrollmentWire,
    enrollment,
    phoneProofWire,
    phoneProof
  });
}

function associationCreationPreimage(enrollmentWire, enrollment) {
  return canonical({
    associationVersion: 1,
    deviceId: enrollment.deviceId,
    ed25519PublicKey: enrollment.ed25519PublicKey,
    enrollmentDigest: digestEnrollmentV2(enrollmentWire),
    predecessorAssociationId: null,
    schema: ASSOCIATION_CREATION_SCHEMA,
    subject: enrollment.subject,
    version: 1
  });
}

function crossContract(value, associationId) {
  const { context, enrollment, phoneProof, preEnrollment } = value;
  if (
    context.challengeKind !== "enrollment-v2" ||
    context.challengeId !== enrollment.enrollmentChallengeId ||
    context.audience !== enrollment.audience ||
    context.subject !== preEnrollment.subject ||
    context.deviceId !== preEnrollment.deviceId ||
    context.bindingId !== preEnrollment.x25519BindingId ||
    context.bindingVersion !== preEnrollment.x25519BindingVersion ||
    context.x25519PublicKeyCommitment !==
      preEnrollment.x25519PublicKeyCommitment ||
    context.ed25519PublicKey !== preEnrollment.ed25519PublicKey ||
    context.associationId !== associationId ||
    context.associationVersion !== 1 ||
    context.predecessorAssociationId !== null ||
    context.authorityEpoch !== 1 ||
    enrollment.subject !== preEnrollment.subject ||
    enrollment.deviceId !== preEnrollment.deviceId ||
    enrollment.ed25519PublicKey !== preEnrollment.ed25519PublicKey ||
    enrollment.x25519BindingId !== preEnrollment.x25519BindingId ||
    enrollment.x25519BindingVersion !== preEnrollment.x25519BindingVersion ||
    enrollment.x25519PublicKeyCommitment !==
      preEnrollment.x25519PublicKeyCommitment ||
    enrollment.issuedAt < preEnrollment.issuedAt ||
    enrollment.expiresAt > preEnrollment.expiresAt ||
    phoneProof.enrollmentChallengeId !== enrollment.enrollmentChallengeId ||
    phoneProof.enrollmentDigest !== digestEnrollmentV2(value.enrollmentWire) ||
    phoneProof.publicKey !== enrollment.ed25519PublicKey
  ) deny();
}

function associationLinkWire(value) {
  return canonical({
    acceptanceId: value.acceptanceId,
    associationId: value.associationId,
    associationVersion: 1,
    authorityEpoch: 1,
    enrollmentChallengeId: value.enrollment.enrollmentChallengeId,
    enrollmentDigest: value.enrollmentDigest,
    preEnrollmentDigest: value.preEnrollmentDigest,
    schema: PREACCEPTED_ENROLLMENT_V2_ASSOCIATION_LINK_SCHEMA,
    version: 2
  });
}

function createBrandedResult(value) {
  const result = {
    acceptanceId: value.acceptanceId,
    acceptanceIdPreimage: value.acceptanceIdPreimage,
    acceptanceWire: value.acceptanceWire,
    approvalEventId: value.approvalEventId,
    approvalEventIdInput: value.approvalEventIdInput,
    associationCreationPreimage: value.associationCreationPreimage,
    associationId: value.associationId,
    associationLinkWire: value.associationLinkWire,
    authority: "not-granted",
    authorizationDigest: value.authorizationDigest,
    canonicalStructureValidity: "valid",
    enrollmentDigest: value.enrollmentDigest,
    inputDigest: value.inputDigest,
    kind: "social-preaccepted-enrollment-cryptographic-result-v2",
    phoneProofOfPossessionValidity: "valid",
    preEnrollmentDigest: value.preEnrollmentDigest,
    strictBip340CryptographicValidity: "valid",
    strictEd25519CryptographicValidity: "valid",
    subject: value.subject
  };
  safeObjectDefineProperty(result, "then", {
    configurable: false,
    enumerable: false,
    value: undefined,
    writable: false
  });
  safeObjectFreeze(result);
  safeApply(safeWeakSetAdd, verifiedResults, [result]);
  return result;
}

/**
 * Verify only an exact canonical wire. No caller object, semantic result,
 * boolean, authority assertion or verification override is accepted.
 */
export async function verifyMessagingDevicePreacceptedEnrollmentV2(source) {
  try {
    if (!verificationPrimordialsIntact()) deny();
    const value = preflight(source);
    if (!verificationPrimordialsIntact()) deny();
    const associationCreation = associationCreationPreimage(
      value.enrollmentWire,
      value.enrollment
    );
    const associationId = domainDigest(
      ASSOCIATION_ID_DOMAIN,
      associationCreation
    );
    crossContract(value, associationId);
    const localEvidence = localAuthorizationEvidence(value);
    if (
      value.acceptanceId !== localEvidence.acceptanceId ||
      value.event.id !== localEvidence.approvalEventId
    ) deny();

    // The Ed25519 gates consume only primitives copied from the safely parsed
    // caller wire and a preimage serialized and encoded through captured
    // operations. The legacy helper must independently produce the same bytes.
    const phonePreimage = canonical({
      domain: ENROLLMENT_PROOF_DOMAIN,
      enrollment: value.enrollmentWire,
      profile: DEVICE_PROOF_PROFILE,
      publicKey: value.enrollment.ed25519PublicKey,
      schema: ENROLLMENT_PROOF_PREIMAGE_SCHEMA,
      version: 2
    });
    if (
      createEnrollmentProofSigningPreimageV2(value.enrollmentWire) !==
      phonePreimage
    ) deny();
    const phonePreimageBytes = safeApply(
      safeTextEncoderEncode,
      encoder,
      [phonePreimage]
    );
    if (!strictVerifyMessagingDeviceEd25519V1(
      phonePreimageBytes,
      value.phoneProof.publicKey,
      value.phoneProof.signature
    )) deny();

    // The existing contract verifier remains required below. This second,
    // module-owned BIP340 confirmation binds its exact pubkey/message/signature
    // to the safely parsed caller event and never calls a live global Boolean.
    if (
      exactNostrEventId(value.event) !== value.event.id ||
      !strictVerifyBip340Exact(
        value.event.pubkey,
        value.event.id,
        value.event.sig
      )
    ) deny();
    if (!verificationPrimordialsIntact()) deny();

    // The exact V1 proposal public key is derived by the authorization parser;
    // callers cannot supply or replace it. Omitting proposal activates only the
    // V1 claim's own strict register parser, followed by all comparisons below.
    const options = {
      subject: value.preEnrollment.subject,
      cryptoImpl: trustedCrypto
    };
    const envelope = await parseAuthorizationEnvelopeV2(
      value.authorizationWire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (
      envelope.wire !== value.authorizationWire ||
      envelope.preEnrollment.wire !== value.preEnrollmentWire ||
      envelope.preEnrollment.requestId !== value.preEnrollment.requestId ||
      envelope.preEnrollment.x25519BindingId !==
        value.preEnrollment.x25519BindingId
    ) deny();

    // BIP340 is checked here, after all bounded nested parsing and link checks.
    const approval = await parseApprovalEventV2(
      value.approvalEventWire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (
      approval.wire !== value.approvalEventWire ||
      approval.eventId !== value.event.id ||
      approval.signature !== value.event.sig ||
      approval.envelope.wire !== envelope.wire
    ) deny();
    const expectedAcceptanceId = await acceptanceIdV2(
      approval.wire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (
      value.acceptanceId !== expectedAcceptanceId ||
      expectedAcceptanceId !== localEvidence.acceptanceId
    ) deny();

    const preEnrollmentDigest = await preEnrollmentDigestV2(
      value.preEnrollmentWire,
      trustedCrypto
    );
    if (!verificationPrimordialsIntact()) deny();
    if (preEnrollmentDigest !== localEvidence.preEnrollmentDigest) deny();
    const authorizationDigest = await authorizationDigestV2(
      envelope.wire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (authorizationDigest !== localEvidence.authorizationDigest) deny();
    const approvalEventIdInput = await approvalEventIdInputV2(
      envelope.wire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (approvalEventIdInput !== localEvidence.approvalEventIdInput) deny();
    const approvalEventId = await approvalEventIdV2(envelope.wire, options);
    if (!verificationPrimordialsIntact()) deny();
    if (
      approvalEventId !== approval.eventId ||
      approvalEventId !== localEvidence.approvalEventId ||
      sha256(approvalEventIdInput) !== approvalEventId
    ) deny();
    const acceptanceIdPreimage = await acceptanceIdPreimageV2(
      approval.wire,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (
      acceptanceIdPreimage !== localEvidence.acceptanceIdPreimage ||
      domainDigest(ACCEPTANCE_ID_DOMAIN, acceptanceIdPreimage) !==
        expectedAcceptanceId
    ) deny();
    const acceptanceWire = await createAcceptanceV2(
      approval.wire,
      value.preEnrollment.issuedAt,
      options
    );
    if (!verificationPrimordialsIntact()) deny();
    if (acceptanceWire !== localEvidence.acceptanceWire) deny();
    const enrollmentDigest = digestEnrollmentV2(value.enrollmentWire);
    const inputDigest = INPUT_DIGEST_PREFIX +
      domainDigest(INPUT_DIGEST_DOMAIN, value.wire);
    const resultValue = {
      acceptanceId: localEvidence.acceptanceId,
      acceptanceIdPreimage: localEvidence.acceptanceIdPreimage,
      acceptanceWire: localEvidence.acceptanceWire,
      approvalEventId: localEvidence.approvalEventId,
      approvalEventIdInput: localEvidence.approvalEventIdInput,
      associationCreationPreimage: associationCreation,
      associationId,
      associationLinkWire: "",
      authorizationDigest: localEvidence.authorizationDigest,
      enrollment: value.enrollment,
      enrollmentDigest,
      inputDigest,
      preEnrollmentDigest: localEvidence.preEnrollmentDigest,
      subject: value.preEnrollment.subject
    };
    resultValue.associationLinkWire = associationLinkWire(resultValue);
    if (!verificationPrimordialsIntact()) deny();
    return createBrandedResult(resultValue);
  } catch {
    deny();
  }
}

/**
 * Brand-consuming projection for future dormant composition tests. Spreads,
 * clones, prototype tricks and caller-created lookalikes are rejected.
 */
export function projectMessagingDevicePreacceptedEnrollmentV2(result) {
  try {
    if (
      result === null || typeof result !== "object" || safeIsProxy(result) ||
      !safeApply(safeWeakSetHas, verifiedResults, [result]) ||
      !safeObjectIsFrozen(result)
    ) deny();
    return safeObjectFreeze({ ...result });
  } catch {
    deny();
  }
}
