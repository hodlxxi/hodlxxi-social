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
const APPROVAL_TAG_NAMES = [
  "purpose", "authorization-digest", "pre-enrollment-digest", "request-id",
  "action", "pairing-id"
];
const HEX64 = /^[0-9a-f]{64}$/;
const verifiedResults = new WeakSet();
const encoder = new TextEncoder();
const deny = () => {
  throw new TypeError("messaging device preaccepted enrollment v2 unavailable");
};
const trustedCrypto = Object.freeze({
  subtle: Object.freeze({
    async digest(algorithm, value) {
      if (algorithm !== "SHA-256" || !(value instanceof Uint8Array)) deny();
      const bytes = createHash("sha256").update(value).digest();
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }
  })
});

function recursivelySorted(value) {
  if (Array.isArray(value)) return value.map(recursivelySorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, recursivelySorted(value[key])])
    );
  }
  return value;
}

const canonical = (value) => JSON.stringify(recursivelySorted(value));

function exactData(value, fields) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    keys.some((key) =>
      typeof key !== "string" || !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    ) || fields.some((field) => !Object.hasOwn(descriptors, field))
  ) deny();
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
}

function closedAuthorizationContext(value) {
  const context = exactData(value, AUTHORIZATION_CONTEXT_FIELDS);
  if (AUTHORIZATION_CONTEXT_FIELDS.some(
    (field) => typeof context[field] !== "string"
  )) deny();
}

function closedApprovalTags(value) {
  if (!Array.isArray(value) || value.length !== APPROVAL_TAG_NAMES.length) deny();
  for (let index = 0; index < APPROVAL_TAG_NAMES.length; index += 1) {
    const tag = value[index];
    if (
      !Array.isArray(tag) || tag.length !== 2 ||
      tag[0] !== APPROVAL_TAG_NAMES[index] ||
      typeof tag[1] !== "string" || tag[1].length === 0 ||
      tag[1].length > 128 || /[^\x20-\x7e]/.test(tag[1])
    ) deny();
  }
}

function closedJson(source, fields, maximum, validateNested) {
  if (
    typeof source !== "string" || source.length === 0 ||
    source.length > maximum || /[^\x20-\x7e]/.test(source) ||
    Buffer.byteLength(source, "utf8") > maximum
  ) deny();
  let parsed;
  try { parsed = JSON.parse(source); } catch { deny(); }
  const value = exactData(parsed, fields);
  validateNested?.(value);
  if (canonical(value) !== source) deny();
  return Object.freeze(value);
}

const boundedString = (value, maximum) => {
  if (
    typeof value !== "string" || value.length === 0 ||
    value.length > maximum || /[^\x20-\x7e]/.test(value) ||
    Buffer.byteLength(value, "utf8") > maximum
  ) deny();
  return value;
};

const sha256 = (source) => createHash("sha256")
  .update(source, "ascii").digest("hex");
const domainDigest = (domain, source) => createHash("sha256")
  .update(domain + "\0", "ascii")
  .update(source, "ascii")
  .digest("hex");

function preflight(source) {
  const input = closedJson(source, INPUT_FIELDS, MAX_INPUT_BYTES);
  if (
    input.schema !== PREACCEPTED_ENROLLMENT_V2_SCHEMA ||
    input.version !== 2 || typeof input.acceptanceId !== "string" ||
    !HEX64.test(input.acceptanceId)
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
  const preEnrollment = parsePreEnrollmentV2(preEnrollmentWire);
  const context = parseMessagingDeviceVerificationContextV1(contextWire);
  const enrollment = parseEnrollmentV2(enrollmentWire);
  const phoneProof = parseEnrollmentProofV2(phoneProofWire);
  return Object.freeze({
    wire: source,
    acceptanceId: input.acceptanceId,
    approvalEventWire,
    authorizationWire,
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
  const result = Object.freeze({
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
  });
  verifiedResults.add(result);
  return result;
}

/**
 * Verify only an exact canonical wire. No caller object, semantic result,
 * boolean, authority assertion or verification override is accepted.
 */
export async function verifyMessagingDevicePreacceptedEnrollmentV2(source) {
  try {
    const value = preflight(source);
    const associationCreation = associationCreationPreimage(
      value.enrollmentWire,
      value.enrollment
    );
    const associationId = domainDigest(
      ASSOCIATION_ID_DOMAIN,
      associationCreation
    );
    crossContract(value, associationId);

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
    if (
      envelope.preEnrollment.wire !== value.preEnrollment.wire ||
      envelope.preEnrollment.requestId !== value.preEnrollment.requestId ||
      envelope.preEnrollment.x25519BindingId !==
        value.preEnrollment.x25519BindingId
    ) deny();

    // BIP340 is checked here, after all bounded nested parsing and link checks.
    const approval = await parseApprovalEventV2(
      value.approvalEventWire,
      options
    );
    if (approval.envelope.wire !== envelope.wire) deny();
    const expectedAcceptanceId = await acceptanceIdV2(
      approval.wire,
      options
    );
    if (value.acceptanceId !== expectedAcceptanceId) deny();

    // Reuse the repository-owned strict Noble 2.3.0 primitive. It enforces
    // canonical points/scalars and calls verify(..., { zip215: false }).
    const phonePreimage = createEnrollmentProofSigningPreimageV2(
      value.enrollmentWire
    );
    if (!strictVerifyMessagingDeviceEd25519V1(
      encoder.encode(phonePreimage),
      value.enrollment.ed25519PublicKey,
      value.phoneProof.signature
    )) deny();

    const preEnrollmentDigest = await preEnrollmentDigestV2(
      value.preEnrollment.wire,
      trustedCrypto
    );
    const authorizationDigest = await authorizationDigestV2(
      envelope.wire,
      options
    );
    const approvalEventIdInput = await approvalEventIdInputV2(
      envelope.wire,
      options
    );
    const approvalEventId = await approvalEventIdV2(envelope.wire, options);
    if (
      approvalEventId !== approval.eventId ||
      sha256(approvalEventIdInput) !== approvalEventId
    ) deny();
    const acceptanceIdPreimage = await acceptanceIdPreimageV2(
      approval.wire,
      options
    );
    if (
      domainDigest(ACCEPTANCE_ID_DOMAIN, acceptanceIdPreimage) !==
        expectedAcceptanceId
    ) deny();
    const acceptanceWire = await createAcceptanceV2(
      approval.wire,
      value.preEnrollment.issuedAt,
      options
    );
    const enrollmentDigest = digestEnrollmentV2(value.enrollmentWire);
    const inputDigest = INPUT_DIGEST_PREFIX +
      domainDigest(INPUT_DIGEST_DOMAIN, value.wire);
    const resultValue = {
      acceptanceId: expectedAcceptanceId,
      acceptanceIdPreimage,
      acceptanceWire,
      approvalEventId,
      approvalEventIdInput,
      associationCreationPreimage: associationCreation,
      associationId,
      associationLinkWire: "",
      authorizationDigest,
      enrollment: value.enrollment,
      enrollmentDigest,
      inputDigest,
      preEnrollmentDigest,
      subject: value.preEnrollment.subject
    };
    resultValue.associationLinkWire = associationLinkWire(resultValue);
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
      result === null || typeof result !== "object" || isProxy(result) ||
      !verifiedResults.has(result) || !Object.isFrozen(result)
    ) deny();
    return Object.freeze({ ...result });
  } catch {
    deny();
  }
}
