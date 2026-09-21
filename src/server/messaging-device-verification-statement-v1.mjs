// Dormant pure Social cryptographic-verification statement producer.
// This module performs no I/O, owns no key, consumes no challenge, evaluates
// no current authority, and can never grant final device admission.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  inspectDeviceChallengeCandidateV1,
  isCanonicalDeviceAudienceV1,
  parseDeviceRequestCandidateV1
} from "./messaging-device-admission-v1.mjs";
import {
  DEVICE_PROOF_PROFILE,
  createEnrollmentApprovalUnsignedEventV2,
  digestEnrollmentV2,
  parseDeviceProofV1,
  parseEnrollmentProofV2,
  parseEnrollmentV2,
  verifyEnrollmentV2Authorization,
  verifyMessagingDeviceProofV1
} from "./messaging-device-proof-profile-v1.mjs";

export const VERIFICATION_STATEMENTS_ENABLED_DEFAULT = false;
export const VERIFICATION_STATEMENT_ALGORITHM = "RS256";
export const VERIFICATION_STATEMENT_TYPE =
  "hodlxxi-social-device-verification+jws";
export const VERIFICATION_STATEMENT_PURPOSE =
  "social_device_cryptographic_verification_v1";
export const VERIFICATION_CONTEXT_SCHEMA =
  "hodlxxi.social_device_verification_context.v1";
export const VERIFICATION_INPUT_SCHEMA =
  "hodlxxi.social_device_verification_input.v1";
export const VERIFICATION_STATEMENT_SCHEMA =
  "hodlxxi.social_device_verification_statement.v1";
export const MAX_VERIFICATION_STATEMENT_LIFETIME_MS = 10_000;
export const MAX_VERIFICATION_CONTEXT_BYTES = 4_096;
export const MAX_VERIFICATION_INPUT_BYTES = 24_576;
export const MAX_VERIFICATION_STATEMENT_BYTES = 4_096;

const VERSION = 1;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_CHALLENGE_BYTES = 4_096;
const MAX_PROOF_BYTES = 1_024;
const MAX_APPROVAL_EVENT_BYTES = 8_192;
const MAX_ACTUAL_REQUEST_BYTES = 2_048;
const MAX_ROUTING_REQUEST_BYTES = 2_048;
const CONSUME_PATH = "/internal/v1/social/device-admission/consume";
const CONTEXT_DIGEST_PREFIX =
  "hodlxxi-social-device-verification-context-v1-sha256:";
const CONTEXT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_DEVICE_VERIFICATION_CONTEXT_V1";
const INPUT_DIGEST_PREFIX =
  "hodlxxi-social-device-verification-input-v1-sha256:";
const INPUT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_DEVICE_VERIFICATION_INPUT_V1";
const JTI_DOMAIN =
  "HODLXXI_SOCIAL_DEVICE_VERIFICATION_STATEMENT_JTI_V1";
const DEVICE_RESULT = "strict-ed25519-valid";
const ENROLLMENT_RESULT = "enrollment-v2-ed25519-and-nostr-valid";
const DEVICE_REQUEST_SCHEMA =
  "hodlxxi.social_messaging_device_request_candidate.v1";
const DEVICE_CHALLENGE_SCHEMA =
  "hodlxxi.social_messaging_device_challenge_candidate.v1";
const DEVICE_CHALLENGE_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1";

const CONTEXT_FIELDS = [
  "approverFullProofId", "approverSessionBinding", "associationId",
  "associationVersion", "attemptId", "audience", "authorityEpoch",
  "bindingId", "bindingVersion", "challengeId", "challengeKind",
  "deviceId", "ed25519PublicKey", "fullProofId",
  "predecessorAssociationId", "profile", "schema", "sessionBinding",
  "subject", "version", "x25519PublicKeyCommitment"
];
const INPUT_FIELDS = [
  "actualRequest", "approvalEvent", "challenge", "context", "proof",
  "routingRequest", "schema", "version"
];
const EVENT_FIELDS = [
  "content", "created_at", "id", "kind", "pubkey", "sig", "tags"
];
const ROUTING_FIELDS = [
  "envelopeDigest", "messageId", "recipientDeviceHandles",
  "recipientPackageSnapshotId", "schema", "version"
];
const CHALLENGE_FIELDS = [
  "challengeId", "domain", "expiresAt", "issuedAt", "request", "schema",
  "version"
];
const PRODUCER_FIELDS = [
  "contextWire", "expectedAudience", "expectedClientId", "expectedIssuer",
  "expectedPurpose", "expectedServicePrincipal", "inputWire", "now",
  "signer", "statementLifetimeMs"
];
const SIGNER_FIELDS = [
  "algorithm", "audience", "clientId", "issuer", "kid", "purpose",
  "servicePrincipal", "signExact"
];
const GATE_FIELDS = ["verificationStatementsEnabled"];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const CONFIGURED_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const FULL_PROOF_ID = /^hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}$/;
const BODY_DIGEST =
  /^hodlxxi-social-device-request-body-v1-sha256:[0-9a-f]{64}$/;
const ENVELOPE_DIGEST =
  /^hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const signerStates = new WeakMap();
const enabled = Object.freeze({ enabled: true });
const fail = () => {
  throw new TypeError("messaging device verification statement unavailable");
};

function ownData(value, fields) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    keys.some((key) =>
      typeof key !== "string" || !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    ) ||
    fields.some((field) => !Object.hasOwn(descriptors, field))
  ) fail();
  return Object.fromEntries(
    fields.map((field) => [field, descriptors[field].value])
  );
}

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

function closedJson(source, fields, maximum) {
  try {
    if (
      typeof source !== "string" || source.length === 0 ||
      Buffer.byteLength(source, "utf8") > maximum || /[^\x20-\x7e]/.test(source)
    ) fail();
    const value = JSON.parse(source);
    if (
      value === null || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) fail();
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
    ) fail();
    return Object.freeze(value);
  } catch {
    fail();
  }
}

function ascii(value, maximum, nullable = false) {
  if (nullable && value === null) return null;
  if (
    typeof value !== "string" || value.length === 0 ||
    Buffer.byteLength(value, "utf8") > maximum || /[^\x20-\x7e]/.test(value)
  ) fail();
  return value;
}

function integer(value, positive = false) {
  if (
    !Number.isSafeInteger(value) || value < 0 || value > MAX_SAFE_INTEGER ||
    (positive && value === 0)
  ) fail();
  return value;
}

function hex64(value) {
  if (typeof value !== "string" || !HEX64.test(value)) fail();
  return value;
}

function hex128(value) {
  if (typeof value !== "string" || !HEX128.test(value)) fail();
  return value;
}

function identifier(value) {
  if (typeof value !== "string" || !CONFIGURED_IDENTIFIER.test(value)) fail();
  return value;
}

function statementAudience(value) {
  if (typeof value !== "string" || !value.endsWith(CONSUME_PATH)) fail();
  const origin = value.slice(0, -CONSUME_PATH.length);
  if (!isCanonicalDeviceAudienceV1(origin)) fail();
  return value;
}

function base64urlToken(value, prefix, encodedLength, decodedLength) {
  try {
    if (
      typeof value !== "string" || !value.startsWith(prefix) ||
      value.length !== prefix.length + encodedLength ||
      !/^[A-Za-z0-9_-]+$/.test(value.slice(prefix.length))
    ) fail();
    const encoded = value.slice(prefix.length);
    const decoded = Buffer.from(encoded, "base64url");
    if (
      decoded.byteLength !== decodedLength ||
      decoded.toString("base64url") !== encoded
    ) fail();
    return value;
  } catch {
    fail();
  }
}

function domainDigest(prefix, domain, source) {
  return prefix + createHash("sha256")
    .update(domain + "\0", "ascii")
    .update(source, "ascii")
    .digest("hex");
}

function parseContext(source) {
  const value = closedJson(source, CONTEXT_FIELDS, MAX_VERIFICATION_CONTEXT_BYTES);
  if (
    value.schema !== VERIFICATION_CONTEXT_SCHEMA || value.version !== VERSION ||
    value.profile !== DEVICE_PROOF_PROFILE ||
    !["enrollment-v2", "device-request-v1"].includes(value.challengeKind)
  ) fail();
  const bindingVersion = integer(value.bindingVersion, true);
  const associationVersion = integer(value.associationVersion, true);
  const authorityEpoch = integer(value.authorityEpoch, true);
  if (
    bindingVersion > 1_024 || !isCanonicalDeviceAudienceV1(value.audience) ||
    typeof value.x25519PublicKeyCommitment !== "string" ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment) ||
    typeof value.fullProofId !== "string" ||
    !FULL_PROOF_ID.test(value.fullProofId)
  ) fail();
  const subject = hex64(value.subject);
  const ed25519PublicKey = hex64(value.ed25519PublicKey);
  if (subject === ed25519PublicKey) fail();
  let predecessorAssociationId = value.predecessorAssociationId;
  let approverSessionBinding = value.approverSessionBinding;
  let approverFullProofId = value.approverFullProofId;
  if (value.challengeKind === "device-request-v1") {
    if (
      predecessorAssociationId !== null || approverSessionBinding !== null ||
      approverFullProofId !== null
    ) fail();
  } else {
    if (
      (predecessorAssociationId === null && associationVersion !== 1) ||
      (predecessorAssociationId !== null && associationVersion <= 1) ||
      (predecessorAssociationId === null && authorityEpoch !== 1)
    ) fail();
    if (predecessorAssociationId !== null) {
      predecessorAssociationId = hex64(predecessorAssociationId);
    }
    approverSessionBinding = hex64(approverSessionBinding);
    if (
      typeof approverFullProofId !== "string" ||
      !FULL_PROOF_ID.test(approverFullProofId)
    ) fail();
  }
  return Object.freeze({
    wire: source,
    challengeKind: value.challengeKind,
    challengeId: hex64(value.challengeId),
    attemptId: hex64(value.attemptId),
    audience: value.audience,
    subject,
    deviceId: hex64(value.deviceId),
    bindingId: hex64(value.bindingId),
    bindingVersion,
    x25519PublicKeyCommitment: value.x25519PublicKeyCommitment,
    profile: DEVICE_PROOF_PROFILE,
    ed25519PublicKey,
    associationId: hex64(value.associationId),
    associationVersion,
    predecessorAssociationId,
    authorityEpoch,
    sessionBinding: hex64(value.sessionBinding),
    approverSessionBinding,
    fullProofId: value.fullProofId,
    approverFullProofId
  });
}

function parseRequestChallenge(source) {
  const challenge = closedJson(source, CHALLENGE_FIELDS, MAX_CHALLENGE_BYTES);
  const issuedAt = integer(challenge.issuedAt);
  const expiresAt = integer(challenge.expiresAt);
  if (
    challenge.schema !== DEVICE_CHALLENGE_SCHEMA || challenge.version !== 1 ||
    challenge.domain !== DEVICE_CHALLENGE_DOMAIN ||
    expiresAt <= issuedAt || expiresAt - issuedAt > 60_000
  ) fail();
  hex64(challenge.challengeId);
  const requestWire = ascii(challenge.request, MAX_ACTUAL_REQUEST_BYTES);
  let request;
  try {
    request = parseDeviceRequestCandidateV1(requestWire, enabled);
  } catch {
    fail();
  }
  if (
    request.schema !== DEVICE_REQUEST_SCHEMA || request.version !== 1 ||
    request.method !== "POST" ||
    (request.operation === "ciphertext-submit" &&
      request.path !== "/messaging/v1/ciphertext-submit") ||
    (request.operation === "recipient-self-read" &&
      request.path !== "/messaging/v1/recipient-self-read")
  ) fail();
  return Object.freeze({ challenge, request, requestWire });
}

function parseRoutingRequest(source) {
  const value = closedJson(source, ROUTING_FIELDS, MAX_ROUTING_REQUEST_BYTES);
  if (
    value.schema !== "hodlxxi.social_messaging_recipient_routing_request.v1" ||
    value.version !== 1 || typeof value.envelopeDigest !== "string" ||
    !ENVELOPE_DIGEST.test(value.envelopeDigest) ||
    typeof value.recipientPackageSnapshotId !== "string" ||
    !SNAPSHOT_ID.test(value.recipientPackageSnapshotId) ||
    !Array.isArray(value.recipientDeviceHandles) ||
    value.recipientDeviceHandles.length < 1 ||
    value.recipientDeviceHandles.length > 16
  ) fail();
  base64urlToken(value.messageId, "m_", 43, 32);
  const handles = value.recipientDeviceHandles.map((handle) =>
    base64urlToken(handle, "d_", 22, 16)
  );
  if (handles.some((handle, index) => handle !== [...new Set(handles)].sort()[index])) {
    fail();
  }
  return value;
}

function parseApprovalEvent(source, context, enrollmentWire) {
  const event = closedJson(source, EVENT_FIELDS, MAX_APPROVAL_EVENT_BYTES);
  const unsigned = createEnrollmentApprovalUnsignedEventV2(enrollmentWire);
  if (
    event.pubkey !== context.subject || !HEX64.test(event.pubkey) ||
    typeof event.id !== "string" || !HEX64.test(event.id) ||
    typeof event.sig !== "string" || !HEX128.test(event.sig) ||
    event.content !== unsigned.content || event.created_at !== unsigned.created_at ||
    event.kind !== unsigned.kind ||
    canonical(event.tags) !== canonical(unsigned.tags)
  ) fail();
  return event;
}

function assertEnrollmentBindings(context, enrollment, proof, challengeWire) {
  if (
    context.challengeKind !== "enrollment-v2" ||
    enrollment.enrollmentChallengeId !== context.challengeId ||
    enrollment.audience !== context.audience ||
    enrollment.subject !== context.subject ||
    enrollment.deviceId !== context.deviceId ||
    enrollment.x25519BindingId !== context.bindingId ||
    enrollment.x25519BindingVersion !== context.bindingVersion ||
    enrollment.x25519PublicKeyCommitment !== context.x25519PublicKeyCommitment ||
    enrollment.ed25519PublicKey !== context.ed25519PublicKey ||
    proof.enrollmentChallengeId !== context.challengeId ||
    proof.enrollmentDigest !== digestEnrollmentV2(challengeWire) ||
    proof.publicKey !== context.ed25519PublicKey
  ) fail();
}

function parseInput(source) {
  const value = closedJson(source, INPUT_FIELDS, MAX_VERIFICATION_INPUT_BYTES);
  if (value.schema !== VERIFICATION_INPUT_SCHEMA || value.version !== VERSION) fail();
  const contextWire = ascii(value.context, MAX_VERIFICATION_CONTEXT_BYTES);
  const challengeWire = ascii(value.challenge, MAX_CHALLENGE_BYTES);
  const proofWire = ascii(value.proof, MAX_PROOF_BYTES);
  const approvalEventWire = ascii(
    value.approvalEvent, MAX_APPROVAL_EVENT_BYTES, true
  );
  const actualRequestWire = ascii(
    value.actualRequest, MAX_ACTUAL_REQUEST_BYTES, true
  );
  const routingRequestWire = ascii(
    value.routingRequest, MAX_ROUTING_REQUEST_BYTES, true
  );
  const context = parseContext(contextWire);

  if (context.challengeKind === "enrollment-v2") {
    if (
      approvalEventWire === null || actualRequestWire !== null ||
      routingRequestWire !== null
    ) fail();
    let enrollment;
    let proof;
    try {
      enrollment = parseEnrollmentV2(challengeWire);
      proof = parseEnrollmentProofV2(proofWire);
    } catch {
      fail();
    }
    assertEnrollmentBindings(context, enrollment, proof, challengeWire);
    const approvalEvent = parseApprovalEvent(
      approvalEventWire, context, challengeWire
    );
    return Object.freeze({
      wire: source,
      context,
      challengeWire,
      challenge: enrollment,
      proofWire,
      proof,
      approvalEventWire,
      approvalEvent,
      actualRequestWire: null,
      request: null,
      routingRequestWire: null,
      routingRequest: null,
      operation: "enrollment-activate"
    });
  }

  if (approvalEventWire !== null || actualRequestWire === null) fail();
  const { challenge, request, requestWire } = parseRequestChallenge(challengeWire);
  let actualRequest;
  let proof;
  try {
    actualRequest = parseDeviceRequestCandidateV1(actualRequestWire, enabled);
    proof = parseDeviceProofV1(proofWire);
  } catch {
    fail();
  }
  if (
    requestWire !== actualRequestWire || challenge.challengeId !== context.challengeId ||
    request.audience !== context.audience || request.subject !== context.subject ||
    request.deviceId !== context.deviceId || request.bindingId !== context.bindingId ||
    request.bindingVersion !== context.bindingVersion ||
    request.sessionBinding !== context.sessionBinding ||
    proof.challengeId !== context.challengeId || proof.profile !== context.profile ||
    proof.publicKey !== context.ed25519PublicKey
  ) fail();
  let routingRequest = null;
  if (request.operation === "ciphertext-submit") {
    if (routingRequestWire === null) fail();
    routingRequest = parseRoutingRequest(routingRequestWire);
  } else if (routingRequestWire !== null) {
    fail();
  }
  return Object.freeze({
    wire: source,
    context,
    challengeWire,
    challenge,
    proofWire,
    proof,
    approvalEventWire: null,
    approvalEvent: null,
    actualRequestWire,
    request: actualRequest,
    routingRequestWire,
    routingRequest,
    operation: request.operation
  });
}

export function parseMessagingDeviceVerificationContextV1(source) {
  try {
    return parseContext(source);
  } catch {
    fail();
  }
}

export function parseMessagingDeviceVerificationInputV1(source) {
  try {
    return parseInput(source);
  } catch {
    fail();
  }
}

export function digestMessagingDeviceVerificationContextV1(source) {
  try {
    const value = parseContext(source);
    return domainDigest(CONTEXT_DIGEST_PREFIX, CONTEXT_DIGEST_DOMAIN, value.wire);
  } catch {
    fail();
  }
}

export function digestMessagingDeviceVerificationInputV1(source) {
  try {
    const value = parseInput(source);
    return domainDigest(INPUT_DIGEST_PREFIX, INPUT_DIGEST_DOMAIN, value.wire);
  } catch {
    fail();
  }
}

/**
 * Construct an opaque infrastructure signer port. The returned object exposes
 * immutable public binding metadata and no signing method. Its exact signing
 * operation remains module-private and is invoked only with the internally
 * constructed verification-statement signing input.
 */
export function createMessagingDeviceVerificationStatementSignerV1(input = {}) {
  try {
    const value = ownData(input, SIGNER_FIELDS);
    if (
      value.algorithm !== VERIFICATION_STATEMENT_ALGORITHM ||
      typeof value.signExact !== "function" ||
      !isCanonicalDeviceAudienceV1(value.issuer) ||
      statementAudience(value.audience) !== value.audience ||
      value.purpose !== VERIFICATION_STATEMENT_PURPOSE
    ) fail();
    const metadata = Object.freeze({
      algorithm: VERIFICATION_STATEMENT_ALGORITHM,
      audience: value.audience,
      clientId: identifier(value.clientId),
      issuer: value.issuer,
      kid: identifier(value.kid),
      purpose: VERIFICATION_STATEMENT_PURPOSE,
      servicePrincipal: identifier(value.servicePrincipal)
    });
    signerStates.set(metadata, Object.freeze({
      ...metadata,
      signExact: value.signExact
    }));
    return metadata;
  } catch {
    fail();
  }
}

function requireEnabled(options) {
  const value = ownData(options, GATE_FIELDS);
  if (value.verificationStatementsEnabled !== true) fail();
}

function signerState(signer) {
  if (
    signer === null || typeof signer !== "object" || isProxy(signer) ||
    !signerStates.has(signer)
  ) fail();
  return signerStates.get(signer);
}

function assertConfigured(input, context, signer) {
  if (
    !isCanonicalDeviceAudienceV1(input.expectedIssuer) ||
    input.expectedIssuer !== context.audience ||
    statementAudience(input.expectedAudience) !== input.expectedAudience ||
    identifier(input.expectedClientId) !== input.expectedClientId ||
    identifier(input.expectedServicePrincipal) !== input.expectedServicePrincipal ||
    input.expectedPurpose !== VERIFICATION_STATEMENT_PURPOSE ||
    signer.algorithm !== VERIFICATION_STATEMENT_ALGORITHM ||
    signer.issuer !== input.expectedIssuer ||
    signer.audience !== input.expectedAudience ||
    signer.clientId !== input.expectedClientId ||
    signer.servicePrincipal !== input.expectedServicePrincipal ||
    signer.purpose !== input.expectedPurpose
  ) fail();
}

function tokenId(payloadWithoutTokenId) {
  return createHash("sha256")
    .update(JTI_DOMAIN + "\0", "ascii")
    .update(canonical(payloadWithoutTokenId), "ascii")
    .digest("hex");
}

function base64urlAscii(value) {
  return Buffer.from(value, "ascii").toString("base64url");
}

/**
 * Produce a purpose-bound compact RS256 JWS only after the real authoritative
 * Social verifier succeeds for every exact supplied byte string.
 *
 * Success means only Social cryptographic verification succeeded for these
 * bytes, time and purpose. It does not establish Current-Full, current session
 * or binding authority, challenge consumption, operation authority, or final
 * admission.
 */
export async function produceMessagingDeviceVerificationStatementV1(
  input = {},
  options = { verificationStatementsEnabled: VERIFICATION_STATEMENTS_ENABLED_DEFAULT }
) {
  try {
    requireEnabled(options);
    const value = ownData(input, PRODUCER_FIELDS);
    const context = parseContext(value.contextWire);
    const verificationInput = parseInput(value.inputWire);
    if (verificationInput.context.wire !== context.wire) fail();
    const signer = signerState(value.signer);
    assertConfigured(value, context, signer);
    const now = integer(value.now);
    const lifetime = integer(value.statementLifetimeMs, true);
    if (lifetime > MAX_VERIFICATION_STATEMENT_LIFETIME_MS) fail();
    const expiresAt = now + lifetime;
    if (!Number.isSafeInteger(expiresAt)) fail();
    if (expiresAt > verificationInput.challenge.expiresAt) fail();
    const contextDigest = domainDigest(
      CONTEXT_DIGEST_PREFIX, CONTEXT_DIGEST_DOMAIN, context.wire
    );
    const inputDigest = domainDigest(
      INPUT_DIGEST_PREFIX, INPUT_DIGEST_DOMAIN, verificationInput.wire
    );

    if (context.challengeKind === "enrollment-v2") {
      const verified = await verifyEnrollmentV2Authorization({
        enrollmentWire: verificationInput.challengeWire,
        approvalEvents: [verificationInput.approvalEvent],
        phoneProofWire: verificationInput.proofWire,
        authenticatedSessionSubject: context.subject,
        now
      });
      if (
        verified.canonicalStructureValidity !== "valid" ||
        verified.externalSignerApprovalValidity !== "valid" ||
        verified.phoneProofOfPossessionValidity !== "valid" ||
        verified.strictEd25519CryptographicValidity !== "valid" ||
        verified.proofProfile !== context.profile ||
        verified.subject !== context.subject ||
        verified.currentDeviceKeyAssociationValidity !== "not_evaluated" ||
        verified.atomicChallengeConsumption !== "not_implemented" ||
        verified.finalAdmission !== "denied"
      ) fail();
    } else {
      try {
        inspectDeviceChallengeCandidateV1(
          verificationInput.challengeWire,
          verificationInput.actualRequestWire,
          now,
          enabled
        );
      } catch {
        fail();
      }
      const verified = verifyMessagingDeviceProofV1({
        storedChallengeWire: verificationInput.challengeWire,
        actualRequestWire: verificationInput.actualRequestWire,
        proofWire: verificationInput.proofWire,
        expectedPublicKey: context.ed25519PublicKey,
        now
      });
      if (
        verified.canonicalStructureValidity !== "valid" ||
        verified.strictEd25519CryptographicValidity !== "valid" ||
        verified.proofProfile !== context.profile ||
        verified.subject !== context.subject ||
        verified.deviceId !== context.deviceId ||
        verified.bindingId !== context.bindingId ||
        verified.bindingVersion !== context.bindingVersion ||
        verified.sessionBinding !== context.sessionBinding ||
        verified.currentDeviceKeyAssociationValidity !== "not_evaluated" ||
        verified.atomicChallengeConsumption !== "not_implemented" ||
        verified.finalAdmission !== "denied"
      ) fail();
    }

    const payloadWithoutTokenId = Object.freeze({
      attemptId: context.attemptId,
      aud: value.expectedAudience,
      challengeId: context.challengeId,
      challengeKind: context.challengeKind,
      clientId: value.expectedClientId,
      contextDigest,
      expiresAt,
      inputDigest,
      iss: value.expectedIssuer,
      issuedAt: now,
      purpose: VERIFICATION_STATEMENT_PURPOSE,
      result: context.challengeKind === "enrollment-v2" ?
        ENROLLMENT_RESULT : DEVICE_RESULT,
      schema: VERIFICATION_STATEMENT_SCHEMA,
      servicePrincipal: value.expectedServicePrincipal,
      version: VERSION
    });
    const payloadWire = canonical({
      ...payloadWithoutTokenId,
      jti: tokenId(payloadWithoutTokenId)
    });
    const protectedHeaderWire = canonical({
      alg: VERIFICATION_STATEMENT_ALGORITHM,
      kid: signer.kid,
      typ: VERIFICATION_STATEMENT_TYPE
    });
    const signingInput =
      `${base64urlAscii(protectedHeaderWire)}.${base64urlAscii(payloadWire)}`;
    let suppliedSignature;
    try {
      suppliedSignature = await signer.signExact(
        Buffer.from(signingInput, "ascii")
      );
    } catch {
      fail();
    }
    if (
      !(suppliedSignature instanceof Uint8Array) ||
      isProxy(suppliedSignature) || suppliedSignature.byteLength === 0
    ) fail();
    const signature = Buffer.from(suppliedSignature);
    const statement = `${signingInput}.${signature.toString("base64url")}`;
    if (
      Buffer.byteLength(protectedHeaderWire, "ascii") > 1_024 ||
      Buffer.byteLength(payloadWire, "ascii") > 3_072 ||
      Buffer.byteLength(statement, "ascii") > MAX_VERIFICATION_STATEMENT_BYTES
    ) fail();
    return statement;
  } catch {
    fail();
  }
}
