// Dormant pure contracts. This module is not imported by runtime composition.
// Social currently owns the strict Ed25519 primitive, not final admission.
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import { CURVE, Point, etc, verify } from "@noble/ed25519";
import {
  digestDeviceChallengeCandidateV1,
  inspectDeviceChallengeCandidateV1,
  isCanonicalDeviceAudienceV1
} from "./messaging-device-admission-v1.mjs";
import { verifyNostrEvent } from "../../web/nostr-event-verifier.mjs";

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
const encoder = new TextEncoder();
const deny = () => {
  throw new TypeError("messaging device proof unavailable");
};
const trustedNostrCrypto = Object.freeze({
  subtle: Object.freeze({
    async digest(algorithm, value) {
      if (algorithm !== "SHA-256" || !(value instanceof Uint8Array)) {
        throw new TypeError("Nostr verification unavailable");
      }
      const bytes = createHash("sha256").update(value).digest();
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }
  })
});
const canonical = (value) => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]))
);
const digest = (domain, source) => createHash("sha256")
  .update(domain + "\0", "ascii")
  .update(source, "ascii")
  .digest("hex");
const isInteger = (value) => Number.isSafeInteger(value) && value >= 0;
const isHex64 = (value) => typeof value === "string" && HEX64.test(value);
const isHex128 = (value) => typeof value === "string" && HEX128.test(value);

function ownData(value, required, optional = []) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
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
    encoder.encode(source).byteLength > maximum ||
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
  if (
    typeof value !== "string" || value.length !== expected * 2 ||
    !/^[0-9a-f]+$/.test(value)
  ) deny();
  return Uint8Array.from(
    value.match(/../g),
    (part) => Number.parseInt(part, 16)
  );
}

function littleEndianInteger(value) {
  let result = 0n;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(value[index]);
  }
  return result;
}

function strictPoint(value) {
  const point = Point.fromHex(value, false).assertValidity();
  if (
    point.toHex() !== value || point.isSmallOrder() ||
    !point.isTorsionFree()
  ) deny();
  return point;
}

const sha512Sync = (...messages) => {
  const hash = createHash("sha512");
  for (const message of messages) hash.update(message);
  return new Uint8Array(hash.digest());
};

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
    if (!(message instanceof Uint8Array) || !isHex64(publicKey) || !isHex128(signature)) {
      return false;
    }
    const publicKeyBytes = hexBytes(publicKey, 32);
    const signatureBytes = hexBytes(signature, 64);
    strictPoint(publicKey);
    strictPoint(signature.slice(0, 64));
    if (littleEndianInteger(signatureBytes.slice(32)) >= CURVE.n) return false;
    return verify(signatureBytes, message, publicKeyBytes, { zip215: false }) === true;
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
      encoder.encode(preimage),
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
    isProxy(value) ||
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
  if (!Array.isArray(value) || isProxy(value) || value.length !== 1) deny();
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
      encoder.encode(preimage),
      value.ed25519PublicKey,
      phoneProof.signature
    )) deny();
    return Object.freeze({
      atomicChallengeConsumption: "not_implemented",
      canonicalStructureValidity: "valid",
      currentDeviceKeyAssociationValidity: "not_evaluated",
      externalSignerApprovalValidity: "valid",
      finalAdmission: "denied",
      phoneProofOfPossessionValidity: "valid",
      proofProfile: DEVICE_PROOF_PROFILE,
      strictEd25519CryptographicValidity: "valid",
      subject: value.subject
    });
  } catch { deny(); }
}
