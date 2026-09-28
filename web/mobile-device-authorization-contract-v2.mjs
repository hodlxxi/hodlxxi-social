// Dormant, pure browser contract for the merged UBID register + initial V2
// transcript. Importing this file performs no I/O and grants no authority.
import {
  canonicalMessagingDeviceJson as canonical,
  inspectMessagingDeviceAuthorizationClaim,
  MESSAGING_DEVICE_EVENT_KIND,
  MESSAGING_DEVICE_SIGNATURE_FORMAT
} from "./messaging-device-authorization-v1.mjs";
import { computeNostrEventId, verifyNostrEvent } from "./nostr-event-verifier.mjs";

export const PRE_ENROLLMENT_SCHEMA =
  "hodlxxi.social_messaging_device_pre_enrollment.v2";
export const PRE_ENROLLMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_V2";
export const AUTHORIZATION_SCHEMA =
  "hodlxxi.social_messaging_device_authorization_method.v2";
export const AUTHORIZATION_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V2";
export const AUTHORIZATION_METHOD = "qr_desktop_pre_enrollment_v2";
export const APPROVAL_EVENT_PURPOSE =
  "hodlxxi-social-messaging-device-qr-pre-enrollment-approval-v2";
export const ACCEPTANCE_SCHEMA =
  "hodlxxi.social_mobile_authorization_acceptance.v2";
export const SIGNED_ATTEMPT_SCHEMA =
  "hodlxxi.social_messaging_device_pre_enrollment_signed_attempt.v2";
export const MOBILE_DEVICE_AUTHORIZATION_V2_RUNTIME_ENABLED = false;

const PROFILE =
  "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1";
const PRE_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_DIGEST_V2";
const PRE_DIGEST_PREFIX =
  "hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:";
const X25519_COMMITMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1";
const PAIRING_SECRET_DOMAIN = "HODLXXI_SOCIAL_PAIRING_SECRET_V2";
const PHONE_EXCHANGE_DOMAIN = "HODLXXI_SOCIAL_PHONE_EXCHANGE_V2";
const PAIRING_POSSESSION_DOMAIN = "HODLXXI_SOCIAL_PAIRING_POSSESSION_V2";
const ACCEPTANCE_ID_PREIMAGE_SCHEMA =
  "hodlxxi.social_mobile_pre_enrollment_acceptance_id_preimage.v2";
const ACCEPTANCE_ID_DOMAIN =
  "HODLXXI_SOCIAL_MOBILE_PRE_ENROLLMENT_ACCEPTANCE_ID_V2";
const MAX_PRE_ENROLLMENT_BYTES = 8_192;
const MAX_AUTHORIZATION_BYTES = 16_384;
const MAX_APPROVAL_EVENT_BYTES = 24_576;
const MAX_ACCEPTANCE_BYTES = 4_096;
const MAX_SIGNED_ATTEMPT_BYTES = 32_768;
const MAX_PRE_ENROLLMENT_LIFETIME_MS = 600_000;
const MAX_PAIRING_LIFETIME_SECONDS = 300;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const PRE_FIELDS = [
  "bindingAuthorizationDigest", "deviceId", "domain", "ed25519PublicKey",
  "expiresAt", "issuedAt", "pairingId", "preEffectAssociationId",
  "preEffectAssociationState", "preEffectAssociationVersion",
  "preEffectAuthorityEpoch", "profile", "proposedAssociationVersion",
  "proposedAuthorityEpoch", "proposedPredecessorAssociationId", "requestId",
  "schema", "subject", "transitionKind", "version", "x25519BindingId",
  "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const CONTEXT_FIELDS = [
  "createdAt", "desktopContext", "exchangeCommitment", "expiresAt",
  "pairingId", "secretCommitment"
];
const AUTHORIZATION_FIELDS = [
  "content", "context", "domain", "method", "preEnrollment", "schema",
  "version"
];
const EVENT_FIELDS = [
  "content", "created_at", "id", "kind", "pubkey", "sig", "tags"
];
const ACCEPTANCE_FIELDS = [
  "acceptanceId", "approvalEventId", "authorizationDigest", "bindingId",
  "deviceId", "ed25519PublicKey", "pairingId", "preEnrollmentDigest",
  "profile", "requestId", "schema", "subject", "version",
  "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const ATTEMPT_FIELDS = [
  "approvalEventId", "approvalEventSignature", "approvalEventWire",
  "authorizationDigest", "authorizationWire", "deviceId",
  "ed25519PublicKey", "pairingId", "preEnrollmentDigest", "requestId",
  "schema", "signatureFormat", "state", "subject", "version",
  "x25519BindingId", "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const APPROVAL_TAG_NAMES = [
  "purpose", "authorization-digest", "pre-enrollment-digest", "request-id",
  "action", "pairing-id"
];
const encoder = new TextEncoder();
const deny = () => {
  throw new TypeError("mobile device authorization v2 unavailable");
};

const freeze = (value) => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};

function exactData(value, fields) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
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
      ) || fields.some((field) => !Object.hasOwn(descriptors, field))
    ) deny();
    return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
  } catch {
    deny();
  }
}

function closedAuthorizationContext(value) {
  const context = exactData(value, CONTEXT_FIELDS);
  if (CONTEXT_FIELDS.some((field) => typeof context[field] !== "string")) deny();
}

function closedApprovalTags(value) {
  const arrayValues = (input, length) => {
    if (
      !Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype ||
      input.length !== length
    ) deny();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.length !== length + 1 ||
      descriptors.length?.value !== length ||
      keys.some((key) => typeof key !== "string" || (
        key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key)
      ))
    ) deny();
    return Array.from({ length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) deny();
      return descriptor.value;
    });
  };
  const tags = arrayValues(value, APPROVAL_TAG_NAMES.length);
  const result = [];
  for (let index = 0; index < APPROVAL_TAG_NAMES.length; index += 1) {
    const tag = arrayValues(tags[index], 2);
    if (
      tag[0] !== APPROVAL_TAG_NAMES[index] ||
      typeof tag[1] !== "string" || tag[1].length === 0 ||
      tag[1].length > 128 || /[^\x20-\x7e]/.test(tag[1])
    ) deny();
    result.push([tag[0], tag[1]]);
  }
  return freeze(result);
}

function closedJson(source, fields, maximum, validateNested) {
  try {
    if (
      typeof source !== "string" || source.length === 0 ||
      source.length > maximum || /[^\x20-\x7e]/.test(source) ||
      encoder.encode(source).byteLength > maximum
    ) deny();
    const parsed = JSON.parse(source);
    const value = exactData(parsed, fields);
    validateNested?.(value);
    if (canonical(value) !== source) deny();
    return freeze(value);
  } catch {
    deny();
  }
}

const hex64 = (value) => {
  if (typeof value !== "string" || !HEX64.test(value)) deny();
  return value;
};
const hex128 = (value) => {
  if (typeof value !== "string" || !HEX128.test(value)) deny();
  return value;
};
const integer = (value, positive = false) => {
  if (!Number.isSafeInteger(value) || value < 0 || (positive && value === 0)) deny();
  return value;
};
const seconds = (value) => {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) deny();
  const milliseconds = Date.parse(value);
  if (
    !Number.isSafeInteger(milliseconds) ||
    new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")
  ) deny();
  return milliseconds / 1_000;
};
const toHex = (value) => Array.from(
  new Uint8Array(value),
  (byte) => byte.toString(16).padStart(2, "0")
).join("");
const fromHex = (value) => Uint8Array.from(
  value.match(/../g),
  (part) => Number.parseInt(part, 16)
);

async function sha256(value, cryptoImpl) {
  try {
    if (typeof cryptoImpl?.subtle?.digest !== "function") deny();
    const result = await cryptoImpl.subtle.digest("SHA-256", encoder.encode(value));
    if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) deny();
    return toHex(result);
  } catch {
    deny();
  }
}

const domainDigest = (domain, source, cryptoImpl) =>
  sha256(`${domain}\0${source}`, cryptoImpl);

function parsePreEnrollment(source) {
  const value = closedJson(source, PRE_FIELDS, MAX_PRE_ENROLLMENT_BYTES);
  const issuedAt = integer(value.issuedAt);
  const expiresAt = integer(value.expiresAt);
  const subject = hex64(value.subject);
  const ed25519PublicKey = hex64(value.ed25519PublicKey);
  if (
    value.schema !== PRE_ENROLLMENT_SCHEMA || value.version !== 2 ||
    value.domain !== PRE_ENROLLMENT_DOMAIN || value.profile !== PROFILE ||
    !HEX64.test(value.bindingAuthorizationDigest) ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment) ||
    ed25519PublicKey === subject || expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_PRE_ENROLLMENT_LIFETIME_MS ||
    integer(value.x25519BindingVersion, true) !== 1 ||
    value.transitionKind !== "initial" ||
    value.preEffectAssociationState !== "absent" ||
    value.preEffectAssociationId !== null ||
    value.preEffectAssociationVersion !== null ||
    value.preEffectAuthorityEpoch !== 0 ||
    value.proposedAssociationVersion !== 1 ||
    value.proposedAuthorityEpoch !== 1 ||
    value.proposedPredecessorAssociationId !== null
  ) deny();
  return freeze({
    wire: source,
    bindingAuthorizationDigest: value.bindingAuthorizationDigest,
    deviceId: hex64(value.deviceId),
    ed25519PublicKey,
    expiresAt,
    issuedAt,
    pairingId: hex64(value.pairingId),
    requestId: hex64(value.requestId),
    subject,
    x25519BindingId: hex64(value.x25519BindingId),
    x25519BindingVersion: value.x25519BindingVersion,
    x25519PublicKeyCommitment: value.x25519PublicKeyCommitment
  });
}

export function parsePreEnrollmentV2(source) {
  try { return parsePreEnrollment(source); } catch { deny(); }
}

export function createPreEnrollmentV2(input = {}) {
  try {
    const value = exactData(input, [
      "bindingAuthorizationDigest", "deviceId", "ed25519PublicKey",
      "expiresAt", "issuedAt", "pairingId", "requestId", "subject",
      "x25519BindingId", "x25519BindingVersion",
      "x25519PublicKeyCommitment"
    ]);
    const wire = canonical({
      bindingAuthorizationDigest: value.bindingAuthorizationDigest,
      deviceId: value.deviceId,
      domain: PRE_ENROLLMENT_DOMAIN,
      ed25519PublicKey: value.ed25519PublicKey,
      expiresAt: value.expiresAt,
      issuedAt: value.issuedAt,
      pairingId: value.pairingId,
      preEffectAssociationId: null,
      preEffectAssociationState: "absent",
      preEffectAssociationVersion: null,
      preEffectAuthorityEpoch: 0,
      profile: PROFILE,
      proposedAssociationVersion: 1,
      proposedAuthorityEpoch: 1,
      proposedPredecessorAssociationId: null,
      requestId: value.requestId,
      schema: PRE_ENROLLMENT_SCHEMA,
      subject: value.subject,
      transitionKind: "initial",
      version: 2,
      x25519BindingId: value.x25519BindingId,
      x25519BindingVersion: value.x25519BindingVersion,
      x25519PublicKeyCommitment: value.x25519PublicKeyCommitment
    });
    parsePreEnrollment(wire);
    return wire;
  } catch {
    deny();
  }
}

export async function createBoundPreEnrollmentV2(input = {}, options = {}) {
  try {
    const value = exactData(input, [
      "content", "ed25519PublicKey", "expiresAt", "pairingId"
    ]);
    const cryptoImpl = options.cryptoImpl ?? globalThis.crypto;
    const subject = hex64(options.subject);
    const semantic = await inspectMessagingDeviceAuthorizationClaim(
      value.content,
      { subject, proposal: options.proposal, cryptoImpl }
    );
    if (semantic.action !== "register" || semantic.binding.bindingVersion !== 1) deny();
    const wire = createPreEnrollmentV2({
      bindingAuthorizationDigest: await sha256(value.content, cryptoImpl),
      deviceId: semantic.binding.deviceId,
      ed25519PublicKey: value.ed25519PublicKey,
      expiresAt: value.expiresAt,
      issuedAt: semantic.issuedAt * 1_000,
      pairingId: value.pairingId,
      requestId: semantic.requestId,
      subject,
      x25519BindingId: semantic.bindingId,
      x25519BindingVersion: semantic.binding.bindingVersion,
      x25519PublicKeyCommitment:
        "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
        await domainDigest(
          X25519_COMMITMENT_DOMAIN,
          semantic.binding.publicKey,
          cryptoImpl
        )
    });
    const parsed = parsePreEnrollment(wire);
    if (parsed.expiresAt > seconds(semantic.binding.expiresAt) * 1_000) deny();
    return wire;
  } catch {
    deny();
  }
}

export async function preEnrollmentDigestV2(
  source,
  cryptoImpl = globalThis.crypto
) {
  try {
    const value = parsePreEnrollment(source);
    return PRE_DIGEST_PREFIX +
      await domainDigest(PRE_DIGEST_DOMAIN, value.wire, cryptoImpl);
  } catch {
    deny();
  }
}

function pairingContext(value) {
  const context = exactData(value, CONTEXT_FIELDS);
  const createdAt = seconds(context.createdAt);
  const expiresAt = seconds(context.expiresAt);
  if (
    !(createdAt < expiresAt &&
      expiresAt <= createdAt + MAX_PAIRING_LIFETIME_SECONDS)
  ) deny();
  return freeze({
    createdAt,
    desktopContext: hex64(context.desktopContext),
    exchangeCommitment: hex64(context.exchangeCommitment),
    expiresAt,
    pairingId: hex64(context.pairingId),
    secretCommitment: hex64(context.secretCommitment)
  });
}

async function parseAuthorization(source, options = {}) {
  const value = closedJson(
    source,
    AUTHORIZATION_FIELDS,
    MAX_AUTHORIZATION_BYTES,
    (authorization) => closedAuthorizationContext(authorization.context)
  );
  if (
    value.schema !== AUTHORIZATION_SCHEMA || value.version !== 2 ||
    value.domain !== AUTHORIZATION_DOMAIN ||
    value.method !== AUTHORIZATION_METHOD ||
    typeof value.content !== "string" ||
    typeof value.preEnrollment !== "string"
  ) deny();
  const preEnrollment = parsePreEnrollment(value.preEnrollment);
  const context = pairingContext(value.context);
  const subject = options.subject === undefined
    ? preEnrollment.subject : hex64(options.subject);
  if (subject !== preEnrollment.subject) deny();
  const semantic = await inspectMessagingDeviceAuthorizationClaim(
    value.content,
    {
      subject,
      proposal: options.proposal,
      cryptoImpl: options.cryptoImpl ?? globalThis.crypto
    }
  );
  const binding = semantic.binding;
  const bindingValidFromMs = seconds(binding.validFrom) * 1_000;
  const bindingExpiresAtMs = seconds(binding.expiresAt) * 1_000;
  const commitment =
    "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
    await domainDigest(
      X25519_COMMITMENT_DOMAIN,
      binding.publicKey,
      options.cryptoImpl ?? globalThis.crypto
    );
  if (
    semantic.action !== "register" || binding.operation !== "register" ||
    binding.priorBindingId !== null || binding.bindingVersion !== 1 ||
    semantic.requestId !== preEnrollment.requestId ||
    semantic.bindingId !== preEnrollment.x25519BindingId ||
    binding.deviceId !== preEnrollment.deviceId ||
    await sha256(value.content, options.cryptoImpl ?? globalThis.crypto) !==
      preEnrollment.bindingAuthorizationDigest ||
    commitment !== preEnrollment.x25519PublicKeyCommitment ||
    binding.publicKey === preEnrollment.ed25519PublicKey ||
    context.pairingId !== preEnrollment.pairingId ||
    preEnrollment.issuedAt !== semantic.issuedAt * 1_000 ||
    context.createdAt > semantic.issuedAt ||
    semantic.issuedAt >= semantic.expiresAt ||
    semantic.expiresAt > context.expiresAt ||
    preEnrollment.expiresAt > bindingExpiresAtMs
  ) deny();
  return freeze({
    wire: source,
    content: value.content,
    context,
    semantic,
    preEnrollment,
    x25519PublicKey: binding.publicKey,
    x25519BindingValidFromMs: bindingValidFromMs,
    x25519BindingExpiresAtMs: bindingExpiresAtMs
  });
}

export async function parseAuthorizationEnvelopeV2(source, options = {}) {
  try { return await parseAuthorization(source, options); } catch { deny(); }
}

export async function createAuthorizationEnvelopeV2(input = {}, options = {}) {
  try {
    const value = exactData(input, [
      "content", "contextWire", "preEnrollmentWire"
    ]);
    const context = closedJson(value.contextWire, CONTEXT_FIELDS, 2_048);
    const wire = canonical({
      content: value.content,
      context,
      domain: AUTHORIZATION_DOMAIN,
      method: AUTHORIZATION_METHOD,
      preEnrollment: value.preEnrollmentWire,
      schema: AUTHORIZATION_SCHEMA,
      version: 2
    });
    await parseAuthorization(wire, options);
    return wire;
  } catch {
    deny();
  }
}

export async function authorizationDigestV2(
  source,
  options = {}
) {
  try {
    const value = await parseAuthorization(source, options);
    return await sha256(value.wire, options.cryptoImpl ?? globalThis.crypto);
  } catch {
    deny();
  }
}

export async function validateAuthorizationTimeV2(
  source,
  nowMs,
  options = {}
) {
  try {
    const value = await parseAuthorization(source, options);
    const now = integer(nowMs);
    if (
      now < value.context.createdAt * 1_000 ||
      now >= value.context.expiresAt * 1_000 ||
      now < value.semantic.issuedAt * 1_000 ||
      now >= value.semantic.expiresAt * 1_000 ||
      now < value.preEnrollment.issuedAt || now >= value.preEnrollment.expiresAt ||
      now < value.x25519BindingValidFromMs ||
      now >= value.x25519BindingExpiresAtMs
    ) deny();
    return value;
  } catch {
    deny();
  }
}

export async function pairingSecretCommitmentV2(
  secret,
  cryptoImpl = globalThis.crypto
) {
  try {
    return await domainDigest(PAIRING_SECRET_DOMAIN, hex64(secret), cryptoImpl);
  } catch {
    deny();
  }
}

export async function phoneExchangeCommitmentV2(
  verifier,
  cryptoImpl = globalThis.crypto
) {
  try {
    return await domainDigest(PHONE_EXCHANGE_DOMAIN, hex64(verifier), cryptoImpl);
  } catch {
    deny();
  }
}

export async function pairingPossessionProofV2(
  secret,
  authorizationDigest,
  cryptoImpl = globalThis.crypto
) {
  try {
    const key = await cryptoImpl.subtle.importKey(
      "raw",
      fromHex(hex64(secret)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const result = await cryptoImpl.subtle.sign(
      "HMAC",
      key,
      encoder.encode(`${PAIRING_POSSESSION_DOMAIN}\0${hex64(authorizationDigest)}`)
    );
    if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) deny();
    return toHex(result);
  } catch {
    deny();
  }
}

export async function verifyPairingPossessionV2(
  authorizationWire,
  input = {}
) {
  try {
    const value = exactData(input, [
      "cryptoImpl", "nowMs", "possessionProof", "proposal", "secret",
      "subject"
    ]);
    const {
      secret, possessionProof, nowMs, cryptoImpl, proposal, subject
    } = value;
    const options = { cryptoImpl, proposal, subject };
    const envelope = await validateAuthorizationTimeV2(
      authorizationWire,
      nowMs,
      options
    );
    const selectedCrypto = cryptoImpl ?? globalThis.crypto;
    const digest = await authorizationDigestV2(authorizationWire, options);
    if (
      await pairingSecretCommitmentV2(secret, selectedCrypto) !==
        envelope.context.secretCommitment ||
      await pairingPossessionProofV2(secret, digest, selectedCrypto) !==
        hex64(possessionProof)
    ) deny();
    return envelope;
  } catch {
    deny();
  }
}

async function approvalTags(envelope, cryptoImpl) {
  return freeze([
    ["purpose", APPROVAL_EVENT_PURPOSE],
    ["authorization-digest", await sha256(envelope.wire, cryptoImpl)],
    ["pre-enrollment-digest",
      await preEnrollmentDigestV2(envelope.preEnrollment.wire, cryptoImpl)],
    ["request-id", envelope.preEnrollment.requestId],
    ["action", "register"],
    ["pairing-id", envelope.preEnrollment.pairingId]
  ]);
}

export async function approvalUnsignedEventV2(source, options = {}) {
  try {
    const envelope = await parseAuthorization(source, options);
    return freeze({
      content: envelope.wire,
      created_at: envelope.semantic.issuedAt,
      kind: MESSAGING_DEVICE_EVENT_KIND,
      tags: await approvalTags(
        envelope,
        options.cryptoImpl ?? globalThis.crypto
      )
    });
  } catch {
    deny();
  }
}

export async function approvalEventIdInputV2(source, options = {}) {
  try {
    const envelope = await parseAuthorization(source, options);
    return JSON.stringify([
      0,
      envelope.preEnrollment.subject,
      envelope.semantic.issuedAt,
      MESSAGING_DEVICE_EVENT_KIND,
      await approvalTags(envelope, options.cryptoImpl ?? globalThis.crypto),
      envelope.wire
    ]);
  } catch {
    deny();
  }
}

export async function approvalEventIdV2(source, options = {}) {
  try {
    return await sha256(
      await approvalEventIdInputV2(source, options),
      options.cryptoImpl ?? globalThis.crypto
    );
  } catch {
    deny();
  }
}

async function parseApproval(source, options = {}) {
  const event = closedJson(
    source,
    EVENT_FIELDS,
    MAX_APPROVAL_EVENT_BYTES,
    (value) => closedApprovalTags(value.tags)
  );
  const envelope = await parseAuthorization(event.content, options);
  const unsignedEvent = await approvalUnsignedEventV2(envelope.wire, options);
  const expectedId = await computeNostrEventId(
    {
      ...unsignedEvent,
      id: "0".repeat(64),
      pubkey: envelope.preEnrollment.subject,
      sig: "0".repeat(128)
    },
    { cryptoImpl: options.cryptoImpl ?? globalThis.crypto }
  );
  if (
    event.content !== envelope.wire ||
    event.created_at !== unsignedEvent.created_at ||
    event.kind !== unsignedEvent.kind ||
    event.pubkey !== envelope.preEnrollment.subject ||
    event.id !== expectedId || hex128(event.sig) !== event.sig ||
    canonical(event.tags) !== canonical(unsignedEvent.tags)
  ) deny();
  let verified;
  try {
    verified = await verifyNostrEvent(event, {
      cryptoImpl: options.cryptoImpl ?? globalThis.crypto
    });
  } catch {
    deny();
  }
  if (
    verified.id !== expectedId || verified.pubkey !== event.pubkey ||
    verified.sig !== event.sig
  ) deny();
  return freeze({
    wire: source,
    eventId: expectedId,
    signature: event.sig,
    event: verified,
    envelope
  });
}

export async function parseApprovalEventV2(source, options = {}) {
  try { return await parseApproval(source, options); } catch { deny(); }
}

export async function createApprovalEventV2(
  authorizationWire,
  signature,
  options = {}
) {
  try {
    const envelope = await parseAuthorization(authorizationWire, options);
    const wire = canonical({
      content: envelope.wire,
      created_at: envelope.semantic.issuedAt,
      id: await approvalEventIdV2(envelope.wire, options),
      kind: MESSAGING_DEVICE_EVENT_KIND,
      pubkey: envelope.preEnrollment.subject,
      sig: hex128(signature),
      tags: await approvalTags(envelope, options.cryptoImpl ?? globalThis.crypto)
    });
    await parseApproval(wire, options);
    return wire;
  } catch {
    deny();
  }
}

export async function acceptanceIdPreimageV2(approvalEventWire, options = {}) {
  try {
    const approval = await parseApproval(approvalEventWire, options);
    const envelope = approval.envelope;
    return canonical({
      approvalEventId: approval.eventId,
      authorizationDigest: await sha256(
        envelope.wire,
        options.cryptoImpl ?? globalThis.crypto
      ),
      bindingId: envelope.preEnrollment.x25519BindingId,
      pairingId: envelope.preEnrollment.pairingId,
      preEnrollmentDigest: await preEnrollmentDigestV2(
        envelope.preEnrollment.wire,
        options.cryptoImpl ?? globalThis.crypto
      ),
      requestId: envelope.preEnrollment.requestId,
      schema: ACCEPTANCE_ID_PREIMAGE_SCHEMA,
      subject: envelope.preEnrollment.subject,
      version: 2
    });
  } catch {
    deny();
  }
}

export async function acceptanceIdV2(approvalEventWire, options = {}) {
  try {
    return await domainDigest(
      ACCEPTANCE_ID_DOMAIN,
      await acceptanceIdPreimageV2(approvalEventWire, options),
      options.cryptoImpl ?? globalThis.crypto
    );
  } catch {
    deny();
  }
}

async function acceptanceWire(approval, options) {
  const pre = approval.envelope.preEnrollment;
  return canonical({
    acceptanceId: await acceptanceIdV2(approval.wire, options),
    approvalEventId: approval.eventId,
    authorizationDigest: await sha256(
      approval.envelope.wire,
      options.cryptoImpl ?? globalThis.crypto
    ),
    bindingId: pre.x25519BindingId,
    deviceId: pre.deviceId,
    ed25519PublicKey: pre.ed25519PublicKey,
    pairingId: pre.pairingId,
    preEnrollmentDigest: await preEnrollmentDigestV2(
      pre.wire,
      options.cryptoImpl ?? globalThis.crypto
    ),
    profile: PROFILE,
    requestId: pre.requestId,
    schema: ACCEPTANCE_SCHEMA,
    subject: pre.subject,
    version: 2,
    x25519BindingVersion: pre.x25519BindingVersion,
    x25519PublicKeyCommitment: pre.x25519PublicKeyCommitment
  });
}

export async function createAcceptanceV2(
  approvalEventWire,
  nowMs,
  options = {}
) {
  try {
    const approval = await parseApproval(approvalEventWire, options);
    await validateAuthorizationTimeV2(approval.envelope.wire, nowMs, options);
    const wire = await acceptanceWire(approval, options);
    closedJson(wire, ACCEPTANCE_FIELDS, MAX_ACCEPTANCE_BYTES);
    return wire;
  } catch {
    deny();
  }
}

export async function parseAcceptanceV2(
  source,
  approvalEventWire,
  options = {}
) {
  try {
    closedJson(source, ACCEPTANCE_FIELDS, MAX_ACCEPTANCE_BYTES);
    const approval = await parseApproval(approvalEventWire, options);
    if (source !== await acceptanceWire(approval, options)) deny();
    return freeze({
      wire: source,
      acceptanceId: await acceptanceIdV2(approval.wire, options),
      approval
    });
  } catch {
    deny();
  }
}

async function signedAttemptWire(approval, options) {
  const pre = approval.envelope.preEnrollment;
  return canonical({
    approvalEventId: approval.eventId,
    approvalEventSignature: approval.signature,
    approvalEventWire: approval.wire,
    authorizationDigest: await sha256(
      approval.envelope.wire,
      options.cryptoImpl ?? globalThis.crypto
    ),
    authorizationWire: approval.envelope.wire,
    deviceId: pre.deviceId,
    ed25519PublicKey: pre.ed25519PublicKey,
    pairingId: pre.pairingId,
    preEnrollmentDigest: await preEnrollmentDigestV2(
      pre.wire,
      options.cryptoImpl ?? globalThis.crypto
    ),
    requestId: pre.requestId,
    schema: SIGNED_ATTEMPT_SCHEMA,
    signatureFormat: MESSAGING_DEVICE_SIGNATURE_FORMAT,
    state: "prepared-provisional-signed",
    subject: pre.subject,
    version: 2,
    x25519BindingId: pre.x25519BindingId,
    x25519BindingVersion: pre.x25519BindingVersion,
    x25519PublicKeyCommitment: pre.x25519PublicKeyCommitment
  });
}

export async function createSignedAttemptV2(
  authorizationWire,
  signedEvent,
  options = {}
) {
  try {
    const event = exactData(signedEvent, EVENT_FIELDS);
    const tags = closedApprovalTags(event.tags);
    const eventWire = canonical({
      content: event.content,
      created_at: event.created_at,
      id: event.id,
      kind: event.kind,
      pubkey: event.pubkey,
      sig: event.sig,
      tags
    });
    const approval = await parseApproval(eventWire, options);
    if (approval.envelope.wire !== authorizationWire) deny();
    return signedAttemptWire(approval, options);
  } catch {
    deny();
  }
}

export async function parseSignedAttemptV2(source, options = {}) {
  try {
    const value = closedJson(source, ATTEMPT_FIELDS, MAX_SIGNED_ATTEMPT_BYTES);
    if (
      value.schema !== SIGNED_ATTEMPT_SCHEMA || value.version !== 2 ||
      value.state !== "prepared-provisional-signed" ||
      value.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT
    ) deny();
    const approval = await parseApproval(value.approvalEventWire, options);
    if (source !== await signedAttemptWire(approval, options)) deny();
    return freeze({ wire: source, approval });
  } catch {
    deny();
  }
}
