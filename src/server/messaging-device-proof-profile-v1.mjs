// Dormant pure contracts. This module is not imported by runtime composition.
// Social currently owns the strict Ed25519 primitive, not final admission.
import {
  createHash,
  createPublicKey,
  verify as nativeEd25519Verify
} from "node:crypto";
import { isProxy } from "node:util/types";
import { CURVE, Point, etc, verify } from "@noble/ed25519";
import {
  digestDeviceChallengeCandidateV1,
  inspectDeviceChallengeCandidateV1,
  isCanonicalDeviceAudienceV1
} from "./messaging-device-admission-v1.mjs";
import { verifyNostrEvent } from "../../web/nostr-event-verifier.mjs";

const safeCreateHash = createHash;
const safeCreatePublicKey = createPublicKey;
const safeNativeEd25519Verify = nativeEd25519Verify;
const safeIsProxy = isProxy;
const safeApply = Reflect.apply;
const safeGlobalThis = globalThis;
const safeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const safeObjectGetPrototypeOf = Object.getPrototypeOf;
const safeObjectDefineProperty = Object.defineProperty;
const objectPrototype = Object.prototype;
const arrayIteratorPrototype = safeObjectGetPrototypeOf(
  [][Symbol.iterator]()
);
const SafeArrayBuffer = ArrayBuffer;
const SafeUint8Array = Uint8Array;
const safeUint8ArrayPrototype = SafeUint8Array.prototype;
const safeTypedArrayConstructor = safeObjectGetPrototypeOf(SafeUint8Array);
const safeTypedArrayPrototype = safeObjectGetPrototypeOf(
  safeUint8ArrayPrototype
);
const safeTypedArrayLength = safeObjectGetOwnPropertyDescriptor(
  safeTypedArrayPrototype,
  "length"
).get;
const safeStringCharCodeAt = String.prototype.charCodeAt;
const safeTextEncoderEncode = TextEncoder.prototype.encode;
const safeBigInt = BigInt;
const safeEd25519Order = CURVE.n;
const safeNobleVerify = verify;
const safePointFromHex = Point.fromHex;
const safePointAssertValidity = Point.prototype.assertValidity;
const safePointToRawBytes = Point.prototype.toRawBytes;
const safePointIsSmallOrder = Point.prototype.isSmallOrder;
const safePointIsTorsionFree = Point.prototype.isTorsionFree;
const encoder = new TextEncoder();
const sha256HashPrototype = safeObjectGetPrototypeOf(safeCreateHash("sha256"));
const safeSha256HashUpdate = sha256HashPrototype.update;
const safeSha256HashDigest = sha256HashPrototype.digest;
const sha512HashPrototype = safeObjectGetPrototypeOf(safeCreateHash("sha512"));
const safeSha512HashUpdate = sha512HashPrototype.update;
const safeSha512HashDigest = sha512HashPrototype.digest;
const ed25519SpkiDerPrefix = new SafeUint8Array(12);
ed25519SpkiDerPrefix[0] = 0x30;
ed25519SpkiDerPrefix[1] = 0x2a;
ed25519SpkiDerPrefix[2] = 0x30;
ed25519SpkiDerPrefix[3] = 0x05;
ed25519SpkiDerPrefix[4] = 0x06;
ed25519SpkiDerPrefix[5] = 0x03;
ed25519SpkiDerPrefix[6] = 0x2b;
ed25519SpkiDerPrefix[7] = 0x65;
ed25519SpkiDerPrefix[8] = 0x70;
ed25519SpkiDerPrefix[9] = 0x03;
ed25519SpkiDerPrefix[10] = 0x21;
ed25519SpkiDerPrefix[11] = 0x00;

function descriptor(target, key) {
  return [target, key, safeObjectGetOwnPropertyDescriptor(target, key)];
}

// Security boundary: caller/network bytes and public evidence are untrusted;
// the Node process/executable, Node/OpenSSL built-ins, trusted deployment
// source, package-lock-selected dependencies, and intentionally loaded
// application code are trusted. Arbitrary JavaScript rewriting process-wide
// state is process compromise; stronger isolation is a future architecture.
// Noble 2.3.0 performs synchronous verification through mutable primordials.
// These selected descriptor checks are non-exhaustive, non-normative defense
// in depth for known paths, not a complete inventory or monkey-patch boundary.
// The module never freezes or changes the global objects themselves.
const strictVerificationDescriptors = [
  descriptor(safeGlobalThis, "Array"),
  descriptor(safeGlobalThis, "ArrayBuffer"),
  descriptor(safeGlobalThis, "Math"),
  descriptor(safeGlobalThis, "Number"),
  descriptor(safeGlobalThis, "Object"),
  descriptor(safeGlobalThis, "Uint8Array"),
  descriptor(Array, "from"),
  descriptor(Array, Symbol.species),
  descriptor(ArrayBuffer, "isView"),
  descriptor(Math, "abs"),
  descriptor(Object, "freeze"),
  descriptor(Object, "defineProperty"),
  descriptor(Array.prototype, "constructor"),
  descriptor(Array.prototype, Symbol.iterator),
  descriptor(arrayIteratorPrototype, "next"),
  descriptor(Array.prototype, "then"),
  descriptor(Array.prototype, "toJSON"),
  descriptor(Array.prototype, "forEach"),
  descriptor(Array.prototype, "join"),
  descriptor(Array.prototype, "map"),
  descriptor(Array.prototype, "push"),
  descriptor(Array.prototype, "reduce"),
  descriptor(BigInt.prototype, "toString"),
  descriptor(Function.prototype, Symbol.hasInstance),
  descriptor(Number.prototype, "toString"),
  descriptor(objectPrototype, "then"),
  descriptor(objectPrototype, "toJSON"),
  descriptor(SafeArrayBuffer.prototype, "then"),
  descriptor(SafeArrayBuffer.prototype, "toJSON"),
  descriptor(String.prototype, "charCodeAt"),
  descriptor(String.prototype, "padStart"),
  descriptor(String.prototype, Symbol.iterator),
  descriptor(SafeUint8Array, "from"),
  descriptor(SafeUint8Array, "of"),
  descriptor(SafeUint8Array, Symbol.species),
  descriptor(safeUint8ArrayPrototype, "constructor"),
  descriptor(safeUint8ArrayPrototype, Symbol.iterator),
  descriptor(safeTypedArrayConstructor, "from"),
  descriptor(safeTypedArrayConstructor, "of"),
  descriptor(safeTypedArrayConstructor, Symbol.species),
  descriptor(safeTypedArrayPrototype, "constructor"),
  descriptor(safeTypedArrayPrototype, Symbol.iterator),
  descriptor(safeTypedArrayPrototype, "length"),
  descriptor(safeTypedArrayPrototype, "reverse"),
  descriptor(safeTypedArrayPrototype, "set"),
  descriptor(safeTypedArrayPrototype, "slice"),
  descriptor(Point, "fromBytes"),
  descriptor(Point, "fromHex"),
  descriptor(Point.prototype, "add"),
  descriptor(Point.prototype, "assertValidity"),
  descriptor(Point.prototype, "clearCofactor"),
  descriptor(Point.prototype, "double"),
  descriptor(Point.prototype, "equals"),
  descriptor(Point.prototype, "is0"),
  descriptor(Point.prototype, "isSmallOrder"),
  descriptor(Point.prototype, "isTorsionFree"),
  descriptor(Point.prototype, "multiply"),
  descriptor(Point.prototype, "negate"),
  descriptor(Point.prototype, "toAffine"),
  descriptor(Point.prototype, "toBytes"),
  descriptor(Point.prototype, "toRawBytes")
];

export const DEVICE_PROOF_PROFILE =
  "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1";
export const DEVICE_PROOF_ALGORITHM = "Ed25519";
export const DEVICE_PROOF_SCHEMA =
  "hodlxxi.social_messaging_device_proof.v1";
export const DEVICE_PROOF_PREIMAGE_SCHEMA =
  "hodlxxi.social_messaging_device_proof_preimage.v1";
export const DEVICE_PROOF_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1";
export const DEVICE_PROOF_RUNTIME_ENABLED = false;
export const FINAL_AUTHORITY_MODEL = "ATOMIC_OWNER_PENDING";
export const ATOMIC_CHALLENGE_OWNER = "PENDING";
export const FINAL_ADMISSION_OWNER = "PENDING";

export const ENROLLMENT_V2_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment.v2";
export const ENROLLMENT_V2_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2";
export const ENROLLMENT_V2_PROOF_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment_proof.v2";
export const ENROLLMENT_V2_PROOF_PREIMAGE_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2";
export const ENROLLMENT_V2_PROOF_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2";
export const ENROLLMENT_V2_APPROVAL_PURPOSE =
  "hodlxxi-social-messaging-device-enrollment-v2";
export const ENROLLMENT_V2_RUNTIME_ENABLED = false;
export const ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT = true;
export const AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR = true;
export const AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES = true;

export const MAX_PROOF_BYTES = 1024;
export const MAX_ENROLLMENT_BYTES = 4096;
export const MAX_ENROLLMENT_LIFETIME_MS = 60_000;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const PROOF_FIELDS = [
  "algorithm", "challengeId", "profile", "publicKey", "schema",
  "signature", "version"
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
const EVENT_FIELDS = [
  "content", "created_at", "id", "kind", "pubkey", "sig", "tags"
];
const enabled = Object.freeze({ enabled: true });
const deny = () => {
  throw new TypeError("messaging device proof unavailable");
};
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
function strictVerificationPrimordialsIntact() {
  for (let index = 0; index < strictVerificationDescriptors.length; index += 1) {
    const entry = strictVerificationDescriptors[index];
    if (!sameDescriptor(entry[0], entry[1], entry[2])) return false;
  }
  return true;
}
function encodeUtf8(value) {
  return safeApply(safeTextEncoderEncode, encoder, [value]);
}
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
const trustedNostrCrypto = Object.freeze({
  subtle: Object.freeze({
    async digest(algorithm, value) {
      if (
        algorithm !== "SHA-256" || !(value instanceof Uint8Array) ||
        !strictVerificationPrimordialsIntact()
      ) {
        throw new TypeError("Nostr verification unavailable");
      }
      const bytes = sha256Digest([[value, undefined]]);
      const length = typedArrayLength(bytes);
      const result = new SafeArrayBuffer(length);
      const view = new SafeUint8Array(result);
      for (let index = 0; index < length; index += 1) {
        view[index] = bytes[index];
      }
      safeObjectDefineProperty(result, "then", {
        configurable: false,
        enumerable: false,
        value: undefined,
        writable: false
      });
      if (!strictVerificationPrimordialsIntact()) {
        throw new TypeError("Nostr verification unavailable");
      }
      return result;
    }
  })
});
const canonical = (value) => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]))
);
const digest = (domain, source) => {
  if (!strictVerificationPrimordialsIntact()) deny();
  const result = sha256Digest([
    [domain + "\0", "ascii"],
    [source, "ascii"]
  ], "hex");
  if (!strictVerificationPrimordialsIntact()) deny();
  return result;
};
const isInteger = (value) => Number.isSafeInteger(value) && value >= 0;
const isHex64 = (value) => typeof value === "string" && HEX64.test(value);
const isHex128 = (value) => typeof value === "string" && HEX128.test(value);

function ownData(value, required, optional = []) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    safeIsProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = [...required, ...optional];
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) =>
      typeof key !== "string" || !allowed.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    ) ||
    required.some((field) => !Object.hasOwn(descriptors, field))
  ) deny();
  return Object.fromEntries(
    keys.map((key) => [key, descriptors[key].value])
  );
}

function closedJson(source, fields, maximum) {
  if (
    typeof source !== "string" ||
    source.length === 0 ||
    encodeUtf8(source).byteLength > maximum ||
    /[^\x20-\x7e]/.test(source)
  ) deny();
  let value;
  try { value = JSON.parse(source); } catch { deny(); }
  if (
    value === null || Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    keys.some((key) =>
      typeof key !== "string" || !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    ) ||
    fields.some((field) => !Object.hasOwn(descriptors, field)) ||
    canonical(value) !== source
  ) deny();
  return Object.freeze(
    Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
  );
}

function hexBytes(value, expected) {
  if (typeof value !== "string" || value.length !== expected * 2) deny();
  const result = new SafeUint8Array(expected);
  for (let index = 0; index < expected; index += 1) {
    const highCode = safeApply(
      safeStringCharCodeAt,
      value,
      [index * 2]
    );
    const lowCode = safeApply(
      safeStringCharCodeAt,
      value,
      [index * 2 + 1]
    );
    const high = highCode >= 48 && highCode <= 57
      ? highCode - 48
      : highCode >= 97 && highCode <= 102 ? highCode - 87 : -1;
    const low = lowCode >= 48 && lowCode <= 57
      ? lowCode - 48
      : lowCode >= 97 && lowCode <= 102 ? lowCode - 87 : -1;
    if (high < 0 || low < 0) deny();
    result[index] = high * 16 + low;
  }
  return result;
}

const HEX_DIGITS = "0123456789abcdef";
function canonicalHexBytes(value, length) {
  let result = "";
  for (let index = 0; index < length; index += 1) {
    const byte = value[index];
    result += HEX_DIGITS[(byte >>> 4) & 15] + HEX_DIGITS[byte & 15];
  }
  return result;
}

function exactUint8Array(value) {
  return value !== null && typeof value === "object" &&
    !safeIsProxy(value) &&
    safeObjectGetPrototypeOf(value) === safeUint8ArrayPrototype;
}

function typedArrayLength(value) {
  return safeApply(safeTypedArrayLength, value, []);
}

function copyBytes(value, start, length) {
  const result = new SafeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    result[index] = value[start + index];
  }
  return result;
}

function equalBytes(left, right, length) {
  if (
    !exactUint8Array(left) || !exactUint8Array(right) ||
    typedArrayLength(left) !== length || typedArrayLength(right) !== length
  ) return false;
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function littleEndianInteger(value, start, length) {
  let result = 0n;
  for (let index = start + length - 1; index >= start; index -= 1) {
    result = (result << 8n) | safeBigInt(value[index]);
  }
  return result;
}

function nativeExactEd25519Verification(message, publicKey, signature) {
  const publicKeyDer = new SafeUint8Array(44);
  for (let index = 0; index < 12; index += 1) {
    publicKeyDer[index] = ed25519SpkiDerPrefix[index];
  }
  for (let index = 0; index < 32; index += 1) {
    publicKeyDer[12 + index] = publicKey[index];
  }
  const keyObject = safeCreatePublicKey({
    key: publicKeyDer,
    format: "der",
    type: "spki"
  });
  return safeNativeEd25519Verify(
    null,
    message,
    keyObject,
    signature
  ) === true;
}

function strictPoint(value, expectedBytes) {
  const point = safeApply(safePointFromHex, Point, [value, false]);
  safeApply(safePointAssertValidity, point, []);
  const canonicalBytes = safeApply(safePointToRawBytes, point, []);
  if (
    !equalBytes(canonicalBytes, expectedBytes, 32) ||
    safeApply(safePointIsSmallOrder, point, []) ||
    !safeApply(safePointIsTorsionFree, point, [])
  ) deny();
}

let expectedSha512Input = null;
let expectedSha512Calls = 0;

function sha512Sync() {
  const hash = safeCreateHash("sha512");
  if (expectedSha512Input !== null) {
    if (
      arguments.length !== 1 || expectedSha512Calls !== 0 ||
      !equalBytes(
        arguments[0],
        expectedSha512Input,
        typedArrayLength(expectedSha512Input)
      )
    ) deny();
    expectedSha512Calls = 1;
    safeApply(safeSha512HashUpdate, hash, [expectedSha512Input]);
  } else {
    for (let index = 0; index < arguments.length; index += 1) {
      safeApply(safeSha512HashUpdate, hash, [arguments[index]]);
    }
  }
  const digestBytes = safeApply(safeSha512HashDigest, hash, []);
  return copyBytes(digestBytes, 0, 64);
}

// Noble 2.3.0 requires a synchronous SHA-512 implementation on Node 18.
// Install the repository-owned implementation once and make the exact verifier
// dependency immutable before any request can reach the primitive.
Object.defineProperty(etc, "sha512Sync", {
  configurable: false,
  enumerable: true,
  value: sha512Sync,
  writable: false
});

/**
 * The repository-owned strict Ed25519 primitive for the profile and Enrollment V2.
 * This is not a general-purpose signing facility and never accepts a private key.
 */
export function strictVerifyMessagingDeviceEd25519V1(
  message,
  publicKey,
  signature
) {
  try {
    if (!exactUint8Array(message)) {
      return false;
    }
    const publicKeyBytes = hexBytes(publicKey, 32);
    const signatureBytes = hexBytes(signature, 64);
    const messageLength = typedArrayLength(message);
    const messageBytes = copyBytes(message, 0, messageLength);
    if (!nativeExactEd25519Verification(
      messageBytes,
      publicKeyBytes,
      signatureBytes
    )) return false;
    if (!strictVerificationPrimordialsIntact()) return false;
    const signaturePointBytes = copyBytes(signatureBytes, 0, 32);
    // Noble receives immutable primitives derived from the exact module-owned
    // copies accepted by native verification. No caller-owned byte view or
    // iterator crosses this boundary.
    const nobleMessage = canonicalHexBytes(messageBytes, messageLength);
    const noblePublicKey = canonicalHexBytes(publicKeyBytes, 32);
    const nobleSignature = canonicalHexBytes(signatureBytes, 64);
    const hashInput = new SafeUint8Array(64 + messageLength);
    for (let index = 0; index < 32; index += 1) {
      hashInput[index] = signaturePointBytes[index];
      hashInput[32 + index] = publicKeyBytes[index];
    }
    for (let index = 0; index < messageLength; index += 1) {
      hashInput[64 + index] = messageBytes[index];
    }
    strictPoint(noblePublicKey, publicKeyBytes);
    strictPoint(
      canonicalHexBytes(signaturePointBytes, 32),
      signaturePointBytes
    );
    if (littleEndianInteger(signatureBytes, 32, 32) >= safeEd25519Order) {
      return false;
    }
    if (expectedSha512Input !== null) return false;
    expectedSha512Input = hashInput;
    expectedSha512Calls = 0;
    let verified;
    let hashCalls;
    try {
      verified = safeNobleVerify(
        nobleSignature,
        nobleMessage,
        noblePublicKey,
        { zip215: false }
      ) === true;
      hashCalls = expectedSha512Calls;
    } finally {
      expectedSha512Input = null;
      expectedSha512Calls = 0;
    }
    return verified && hashCalls === 1 &&
      strictVerificationPrimordialsIntact();
  } catch {
    return false;
  }
}

export function parseDeviceProofV1(source) {
  const proof = closedJson(source, PROOF_FIELDS, MAX_PROOF_BYTES);
  if (
    proof.algorithm !== DEVICE_PROOF_ALGORITHM ||
    proof.profile !== DEVICE_PROOF_PROFILE ||
    proof.schema !== DEVICE_PROOF_SCHEMA || proof.version !== 1 ||
    !isHex64(proof.challengeId) || !isHex64(proof.publicKey) ||
    !isHex128(proof.signature)
  ) deny();
  return proof;
}

export function createDeviceProofSigningPreimageV1(challengeWire, publicKey) {
  try {
    if (!isHex64(publicKey)) deny();
    // Structural and lifetime validation happens against stored bytes during
    // verification. The proof cannot carry replacement challenge bytes.
    digestDeviceChallengeCandidateV1(challengeWire, enabled);
    const inspected = JSON.parse(challengeWire);
    if (!isHex64(inspected?.challengeId)) deny();
    return canonical({
      challenge: challengeWire,
      domain: DEVICE_PROOF_DOMAIN,
      profile: DEVICE_PROOF_PROFILE,
      publicKey,
      schema: DEVICE_PROOF_PREIMAGE_SCHEMA,
      version: 1
    });
  } catch { deny(); }
}

export function createDeviceProofV1(input = {}) {
  try {
    const { challengeId, publicKey, signature } = ownData(
      input,
      ["challengeId", "publicKey", "signature"]
    );
    const wire = canonical({
      algorithm: DEVICE_PROOF_ALGORITHM,
      challengeId,
      profile: DEVICE_PROOF_PROFILE,
      publicKey,
      schema: DEVICE_PROOF_SCHEMA,
      signature,
      version: 1
    });
    parseDeviceProofV1(wire);
    return wire;
  } catch { deny(); }
}

export function verifyMessagingDeviceProofV1(input = {}) {
  try {
    const {
      storedChallengeWire,
      actualRequestWire,
      proofWire,
      expectedPublicKey,
      now
    } = ownData(input, [
      "storedChallengeWire", "actualRequestWire", "proofWire",
      "expectedPublicKey", "now"
    ]);
    if (!isHex64(expectedPublicKey)) deny();
    const challenge = inspectDeviceChallengeCandidateV1(
      storedChallengeWire,
      actualRequestWire,
      now,
      enabled
    );
    const proof = parseDeviceProofV1(proofWire);
    if (
      proof.challengeId !== challenge.challengeId ||
      proof.publicKey !== expectedPublicKey
    ) deny();
    const preimage = createDeviceProofSigningPreimageV1(
      storedChallengeWire,
      expectedPublicKey
    );
    if (!strictVerifyMessagingDeviceEd25519V1(
      encodeUtf8(preimage),
      expectedPublicKey,
      proof.signature
    )) deny();
    const request = JSON.parse(challenge.request);
    return Object.freeze({
      atomicChallengeConsumption: "not_implemented",
      bindingId: request.bindingId,
      bindingVersion: request.bindingVersion,
      canonicalStructureValidity: "valid",
      challengeDigest: digestDeviceChallengeCandidateV1(storedChallengeWire, enabled),
      currentDeviceKeyAssociationValidity: "not_evaluated",
      deviceId: request.deviceId,
      finalAdmission: "denied",
      proofProfile: DEVICE_PROOF_PROFILE,
      sessionBinding: request.sessionBinding,
      strictEd25519CryptographicValidity: "valid",
      subject: request.subject
    });
  } catch { deny(); }
}

export function x25519PublicKeyCommitmentV1(publicKey) {
  try {
    if (!isHex64(publicKey)) deny();
    return "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
      digest(
        "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1",
        publicKey
      );
  } catch { deny(); }
}

function enrollment(source) {
  const value = closedJson(source, ENROLLMENT_FIELDS, MAX_ENROLLMENT_BYTES);
  if (
    value.schema !== ENROLLMENT_V2_SCHEMA || value.version !== 2 ||
    value.domain !== ENROLLMENT_V2_DOMAIN ||
    value.profile !== DEVICE_PROOF_PROFILE ||
    !isHex64(value.subject) || !isHex64(value.deviceId) ||
    !isHex64(value.x25519BindingId) ||
    !Number.isInteger(value.x25519BindingVersion) ||
    value.x25519BindingVersion < 1 || value.x25519BindingVersion > 1024 ||
    typeof value.x25519PublicKeyCommitment !== "string" ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment) ||
    !isHex64(value.ed25519PublicKey) ||
    !isHex64(value.enrollmentChallengeId) ||
    !isInteger(value.issuedAt) || !isInteger(value.expiresAt) ||
    value.expiresAt <= value.issuedAt ||
    value.expiresAt - value.issuedAt > MAX_ENROLLMENT_LIFETIME_MS
  ) deny();
  if (!isCanonicalDeviceAudienceV1(value.audience)) deny();
  if (value.ed25519PublicKey === value.subject) deny();
  return value;
}

export function parseEnrollmentV2(source) {
  try { return enrollment(source); } catch { deny(); }
}

export function createEnrollmentV2(value) {
  try {
    value = ownData(value, [
      "audience", "deviceId", "ed25519PublicKey", "enrollmentChallengeId",
      "expiresAt", "issuedAt", "subject", "x25519BindingId",
      "x25519BindingVersion", "x25519PublicKeyCommitment"
    ]);
    const wire = canonical({
      audience: value.audience,
      deviceId: value.deviceId,
      domain: ENROLLMENT_V2_DOMAIN,
      ed25519PublicKey: value.ed25519PublicKey,
      enrollmentChallengeId: value.enrollmentChallengeId,
      expiresAt: value.expiresAt,
      issuedAt: value.issuedAt,
      profile: DEVICE_PROOF_PROFILE,
      schema: ENROLLMENT_V2_SCHEMA,
      subject: value.subject,
      version: 2,
      x25519BindingId: value.x25519BindingId,
      x25519BindingVersion: value.x25519BindingVersion,
      x25519PublicKeyCommitment: value.x25519PublicKeyCommitment
    });
    enrollment(wire);
    return wire;
  } catch { deny(); }
}

export function digestEnrollmentV2(source) {
  try {
    enrollment(source);
    return "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
      digest("HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2", source);
  } catch { deny(); }
}

export function createEnrollmentProofSigningPreimageV2(source) {
  try {
    const value = enrollment(source);
    return canonical({
      domain: ENROLLMENT_V2_PROOF_DOMAIN,
      enrollment: source,
      profile: DEVICE_PROOF_PROFILE,
      publicKey: value.ed25519PublicKey,
      schema: ENROLLMENT_V2_PROOF_PREIMAGE_SCHEMA,
      version: 2
    });
  } catch { deny(); }
}

export function parseEnrollmentProofV2(source) {
  const proof = closedJson(source, ENROLLMENT_PROOF_FIELDS, MAX_PROOF_BYTES);
  if (
    proof.algorithm !== DEVICE_PROOF_ALGORITHM ||
    proof.schema !== ENROLLMENT_V2_PROOF_SCHEMA || proof.version !== 2 ||
    proof.profile !== DEVICE_PROOF_PROFILE ||
    !isHex64(proof.enrollmentChallengeId) ||
    typeof proof.enrollmentDigest !== "string" ||
    !/^hodlxxi-social-messaging-device-enrollment-v2-sha256:[0-9a-f]{64}$/.test(
      proof.enrollmentDigest
    ) ||
    !isHex64(proof.publicKey) || !isHex128(proof.signature)
  ) deny();
  return proof;
}

export function createEnrollmentProofV2(input = {}) {
  try {
    const {
      enrollmentChallengeId,
      enrollmentDigest,
      publicKey,
      signature
    } = ownData(input, [
      "enrollmentChallengeId", "enrollmentDigest", "publicKey", "signature"
    ]);
    const wire = canonical({
      algorithm: DEVICE_PROOF_ALGORITHM,
      enrollmentChallengeId,
      enrollmentDigest,
      profile: DEVICE_PROOF_PROFILE,
      publicKey,
      schema: ENROLLMENT_V2_PROOF_SCHEMA,
      signature,
      version: 2
    });
    parseEnrollmentProofV2(wire);
    return wire;
  } catch { deny(); }
}

export function createEnrollmentApprovalUnsignedEventV2(source) {
  try {
    const value = enrollment(source);
    return Object.freeze({
      content: source,
      created_at: Math.floor(value.issuedAt / 1000),
      kind: 27236,
      tags: Object.freeze([
        Object.freeze(["purpose", ENROLLMENT_V2_APPROVAL_PURPOSE]),
        Object.freeze(["enrollment-digest", digestEnrollmentV2(source)]),
        Object.freeze(["challenge-id", value.enrollmentChallengeId]),
        Object.freeze(["device-id", value.deviceId])
      ])
    });
  } catch { deny(); }
}

function exactVerifiedEvent(value) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    safeIsProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).length !== EVENT_FIELDS.length ||
    EVENT_FIELDS.some((field) =>
      !descriptors[field]?.enumerable ||
      !Object.hasOwn(descriptors[field], "value")
    )
  ) deny();
  return Object.fromEntries(
    EVENT_FIELDS.map((field) => [field, descriptors[field].value])
  );
}

function exactOneEvent(value) {
  if (!Array.isArray(value) || safeIsProxy(value) || value.length !== 1) deny();
  const keys = Reflect.ownKeys(value);
  const item = Object.getOwnPropertyDescriptor(value, "0");
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (
    keys.length !== 2 || !item || !Object.hasOwn(item, "value") ||
    !length || !Object.hasOwn(length, "value") || length.value !== 1
  ) deny();
  return item.value;
}

export async function verifyEnrollmentV2Authorization(input = {}) {
  try {
    if (!strictVerificationPrimordialsIntact()) deny();
    const {
      enrollmentWire,
      approvalEvents,
      phoneProofWire,
      authenticatedSessionSubject,
      now
    } = ownData(input, [
      "enrollmentWire", "approvalEvents", "phoneProofWire",
      "authenticatedSessionSubject", "now"
    ]);
    const value = enrollment(enrollmentWire);
    if (
      !isHex64(authenticatedSessionSubject) ||
      authenticatedSessionSubject !== value.subject ||
      !isInteger(now) || now < value.issuedAt || now >= value.expiresAt
    ) deny();
    const suppliedEvent = exactOneEvent(approvalEvents);
    const verified = exactVerifiedEvent(
      await verifyNostrEvent(suppliedEvent, { cryptoImpl: trustedNostrCrypto })
    );
    if (!strictVerificationPrimordialsIntact()) deny();
    const unsigned = createEnrollmentApprovalUnsignedEventV2(enrollmentWire);
    if (
      verified.pubkey !== authenticatedSessionSubject ||
      verified.pubkey !== value.subject || verified.kind !== unsigned.kind ||
      verified.created_at !== unsigned.created_at ||
      verified.content !== unsigned.content ||
      JSON.stringify(verified.tags) !== JSON.stringify(unsigned.tags)
    ) deny();
    const phoneProof = parseEnrollmentProofV2(phoneProofWire);
    if (
      phoneProof.enrollmentChallengeId !== value.enrollmentChallengeId ||
      phoneProof.enrollmentDigest !== digestEnrollmentV2(enrollmentWire) ||
      phoneProof.publicKey !== value.ed25519PublicKey
    ) deny();
    const preimage = createEnrollmentProofSigningPreimageV2(enrollmentWire);
    if (!strictVerifyMessagingDeviceEd25519V1(
      encodeUtf8(preimage),
      value.ed25519PublicKey,
      phoneProof.signature
    )) deny();
    const result = {
      atomicChallengeConsumption: "not_implemented",
      canonicalStructureValidity: "valid",
      currentDeviceKeyAssociationValidity: "not_evaluated",
      externalSignerApprovalValidity: "valid",
      finalAdmission: "denied",
      phoneProofOfPossessionValidity: "valid",
      proofProfile: DEVICE_PROOF_PROFILE,
      strictEd25519CryptographicValidity: "valid",
      subject: value.subject
    };
    safeObjectDefineProperty(result, "then", {
      configurable: false,
      enumerable: false,
      value: undefined,
      writable: false
    });
    if (!strictVerificationPrimordialsIntact()) deny();
    return Object.freeze(result);
  } catch { deny(); }
}
