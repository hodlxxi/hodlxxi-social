// Explicit dormant seams for V2 preparation and one external desktop approval.
// There is deliberately no dispatch, publish, relay or runtime entrypoint here.
import {
  canonicalMessagingDeviceAuthorizationProposal
} from "./messaging-device-authorization-v1.mjs";
import {
  approvalUnsignedEventV2,
  authorizationDigestV2,
  createSignedAttemptV2,
  parseAuthorizationEnvelopeV2,
  parseSignedAttemptV2,
  validateAuthorizationTimeV2
} from "./mobile-device-authorization-contract-v2.mjs";

export const MOBILE_DEVICE_AUTHORIZATION_SEAMS_V2_RUNTIME_ENABLED = false;

const HEX64 = /^[0-9a-f]{64}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const PUBLIC_PREPARATION_SCHEMA =
  "hodlxxi.social_messaging_device_ed25519_provisional_key_public.v2";
const PUBLIC_PREPARATION_FIELDS = [
  "deviceId", "ed25519PublicKey", "recordRevision", "requestId", "schema",
  "state", "subjectHint", "version", "x25519BindingId",
  "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const MAX_NIP07_METHOD_DEPTH = 8;
const reflectApply = Reflect.apply;
const authorityMicrotaskCheckpoint = async () => {};
const deny = () => {
  throw new TypeError("mobile device authorization v2 seam unavailable");
};
const hex64 = (value) => {
  if (typeof value !== "string" || !HEX64.test(value)) deny();
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

function optionalData(value, fields) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) deny();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) =>
      typeof key !== "string" || !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    )) deny();
    return Object.fromEntries(
      fields.filter((field) => Object.hasOwn(descriptors, field))
        .map((field) => [field, descriptors[field].value])
    );
  } catch {
    deny();
  }
}

function context(value) {
  const checked = exactData(value, [
    "access", "authorizationDigest", "pairingId", "revision", "subject"
  ]);
  if (checked.access !== "full") deny();
  hex64(checked.authorizationDigest);
  hex64(checked.pairingId);
  hex64(checked.revision);
  hex64(checked.subject);
  return Object.freeze(checked);
}

function pending(value, subject, proposal) {
  try {
    const checked = exactData(value, [
      "deviceId", "pendingProposal", "publicKey", "requestId", "state",
      "subject"
    ]);
    const expected = canonicalMessagingDeviceAuthorizationProposal(proposal);
    if (
      checked.subject !== subject || checked.state !== "pending-register" ||
      checked.deviceId !== proposal.deviceId ||
      checked.publicKey !== proposal.publicKey ||
      checked.requestId !== proposal.requestId ||
      checked.pendingProposal !== expected
    ) deny();
    return Object.freeze(checked);
  } catch {
    deny();
  }
}

const resolveNip07DataMethod = (provider, name) => {
  try {
    let current = provider;
    for (
      let depth = 0;
      current !== null && depth < MAX_NIP07_METHOD_DEPTH;
      depth += 1
    ) {
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor !== undefined) {
        if (
          !Object.hasOwn(descriptor, "value") ||
          typeof descriptor.value !== "function"
        ) deny();
        return descriptor.value;
      }
      current = Object.getPrototypeOf(current);
    }
  } catch {
    deny();
  }
  deny();
};

export function preEnrollmentComparisonCode(authorizationDigest) {
  return hex64(authorizationDigest).slice(0, 12).toUpperCase()
    .match(/.{4}/g).join("-");
}

export async function prepareProvisionalMessagingDeviceV2(input = {}) {
  try {
    const {
      enabled = false,
      bindingAuthorizationContent,
      keyBoundary
    } = optionalData(input, [
      "bindingAuthorizationContent", "enabled", "keyBoundary"
    ]);
    if (
      enabled !== true || typeof bindingAuthorizationContent !== "string" ||
      typeof keyBoundary?.prepare !== "function"
    ) deny();
    const prepared = await keyBoundary.prepare(bindingAuthorizationContent);
    const value = exactData(prepared, PUBLIC_PREPARATION_FIELDS);
    if (
      value.schema !== PUBLIC_PREPARATION_SCHEMA || value.version !== 2 ||
      value.state !== "prepared-provisional" ||
      value.x25519BindingVersion !== 1 ||
      typeof value.schema !== "string" ||
      typeof value.version !== "number" ||
      typeof value.state !== "string" ||
      typeof value.x25519BindingVersion !== "number" ||
      typeof value.x25519PublicKeyCommitment !== "string" ||
      !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment)
    ) deny();
    for (const field of [
      "deviceId", "ed25519PublicKey", "recordRevision", "requestId",
      "subjectHint", "x25519BindingId"
    ]) hex64(value[field]);
    if (value.ed25519PublicKey === value.subjectHint) deny();
    return Object.freeze({
      schema: value.schema,
      version: value.version,
      state: value.state,
      subjectHint: value.subjectHint,
      deviceId: value.deviceId,
      requestId: value.requestId,
      x25519BindingId: value.x25519BindingId,
      x25519BindingVersion: value.x25519BindingVersion,
      x25519PublicKeyCommitment: value.x25519PublicKeyCommitment,
      ed25519PublicKey: value.ed25519PublicKey,
      recordRevision: value.recordRevision
    });
  } catch {
    deny();
  }
}

export function createDesktopPreEnrollmentApprovalV2(input = {}) {
  let extracted;
  try {
    extracted = optionalData(input, [
      "cryptoImpl", "enabled", "getContext", "keyBoundary", "nowMs",
      "readX25519Pending", "resolveProvider"
    ]);
  } catch {
    deny();
  }
  const {
    enabled = false,
    getContext,
    readX25519Pending,
    keyBoundary,
    resolveProvider,
    nowMs = Date.now,
    cryptoImpl = globalThis.crypto
  } = extracted;
  let cancelled = false;
  const methods = [
    "claimSigningAttempt", "persistSignedAttempt", "readSignedAttempt"
  ];
  const syncCheck = (initial, includeCancellation = true) => {
    const current = context(getContext?.());
    if (
      (includeCancellation && cancelled) || current.subject !== initial.subject ||
      current.revision !== initial.revision ||
      current.pairingId !== initial.pairingId ||
      current.authorizationDigest !== initial.authorizationDigest
    ) deny();
  };
  const readPending = async (initial, proposal, includeCancellation = true) => {
    syncCheck(initial, includeCancellation);
    if (typeof readX25519Pending !== "function") deny();
    const value = await readX25519Pending();
    syncCheck(initial, includeCancellation);
    return pending(value, initial.subject, proposal);
  };
  const recheck = async (initial, proposal, includeCancellation = true) => {
    syncCheck(initial, includeCancellation);
    await readPending(initial, proposal, includeCancellation);
    syncCheck(initial, includeCancellation);
  };
  const timeStillValid = (envelope) => {
    const value = nowMs();
    if (
      !Number.isSafeInteger(value) ||
      value < envelope.context.createdAt * 1_000 ||
      value >= envelope.context.expiresAt * 1_000 ||
      value < envelope.semantic.issuedAt * 1_000 ||
      value >= envelope.semantic.expiresAt * 1_000 ||
      value < envelope.preEnrollment.issuedAt ||
      value >= envelope.preEnrollment.expiresAt ||
      value < envelope.x25519BindingValidFromMs ||
      value >= envelope.x25519BindingExpiresAtMs
    ) deny();
  };
  return Object.freeze({
    cancel() { cancelled = true; },
    async approve(approveInput = {}) {
      try {
        const {
          authorizationWire, comparisonCode, proposal
        } = exactData(approveInput, [
          "authorizationWire", "comparisonCode", "proposal"
        ]);
        if (
          enabled !== true || cancelled || typeof getContext !== "function" ||
          typeof resolveProvider !== "function" ||
          methods.some((name) => typeof keyBoundary?.[name] !== "function")
        ) deny();
        const initial = context(getContext());
        const proposalWire = canonicalMessagingDeviceAuthorizationProposal(proposal);
        const exactProposal = Object.freeze(JSON.parse(proposalWire));
        if (exactProposal.operation !== "register") deny();
        await recheck(initial, exactProposal);
        const options = {
          subject: initial.subject,
          proposal: exactProposal,
          cryptoImpl
        };
        const envelope = await parseAuthorizationEnvelopeV2(
          authorizationWire,
          options
        );
        const timeAndSyncCheck = (includeCancellation = true) => {
          timeStillValid(envelope);
          syncCheck(initial, includeCancellation);
        };
        await recheck(initial, exactProposal);
        timeAndSyncCheck();
        const digest = await authorizationDigestV2(authorizationWire, options);
        await recheck(initial, exactProposal);
        timeAndSyncCheck();
        if (
          digest !== initial.authorizationDigest ||
          envelope.preEnrollment.pairingId !== initial.pairingId ||
          comparisonCode !== preEnrollmentComparisonCode(digest)
        ) deny();

        const existing = await keyBoundary.readSignedAttempt(authorizationWire);
        await recheck(initial, exactProposal);
        timeAndSyncCheck();
        if (existing !== undefined) {
          const parsed = await parseSignedAttemptV2(existing, options);
          await recheck(initial, exactProposal);
          timeAndSyncCheck();
          if (parsed.approval.envelope.wire !== authorizationWire) deny();
          timeAndSyncCheck();
          return existing;
        }

        // This durable claim is intentionally never cleared by this PR. A crash
        // or ambiguous signer outcome therefore cannot silently reacquire NIP-07.
        const claim = await keyBoundary.claimSigningAttempt(authorizationWire);
        await recheck(initial, exactProposal);
        timeAndSyncCheck();
        if (claim?.status === "signed") {
          const signedAttemptWire = claim.signedAttemptWire;
          const parsed = await parseSignedAttemptV2(
            signedAttemptWire,
            options
          );
          await recheck(initial, exactProposal);
          timeAndSyncCheck();
          if (parsed.approval.envelope.wire !== authorizationWire) deny();
          timeAndSyncCheck();
          return signedAttemptWire;
        }
        if (
          claim?.status !== "claimed" ||
          typeof claim.signingClaimWire !== "string"
        ) deny();

        const unsignedEvent = await approvalUnsignedEventV2(
          authorizationWire,
          options
        );
        await recheck(initial, exactProposal);
        timeAndSyncCheck();
        let provider;
        let signedEvent;
        try {
          provider = await resolveProvider();
          await recheck(initial, exactProposal);
          timeAndSyncCheck();
          if (provider === null || typeof provider !== "object") deny();
          const getPublicKey = resolveNip07DataMethod(provider, "getPublicKey");
          await authorityMicrotaskCheckpoint();
          timeAndSyncCheck();
          const signerSubject = await reflectApply(getPublicKey, provider, []);
          await recheck(initial, exactProposal);
          timeAndSyncCheck();
          if (signerSubject !== initial.subject ||
              signerSubject !== envelope.preEnrollment.subject) deny();
          const signEvent = resolveNip07DataMethod(provider, "signEvent");
          await authorityMicrotaskCheckpoint();
          timeAndSyncCheck();
          signedEvent = await reflectApply(
            signEvent,
            provider,
            [unsignedEvent]
          );
          // Required immediate post-prompt checks happen before any other await.
          let postSignerContextValid = true;
          try {
            timeAndSyncCheck(false);
          } catch {
            postSignerContextValid = false;
          }
          provider = undefined;

          // Even if cancellation or a context switch raced the returned event,
          // validate and persist the exact evidence so it can never be re-signed.
          const signedAttemptWire = await createSignedAttemptV2(
            authorizationWire,
            signedEvent,
            options
          );
          const persisted = await keyBoundary.persistSignedAttempt(
            claim.signingClaimWire,
            signedAttemptWire
          );
          if (persisted !== signedAttemptWire) deny();
          if (!postSignerContextValid || cancelled) deny();
          const validationNowMs = nowMs();
          syncCheck(initial);
          await validateAuthorizationTimeV2(
            authorizationWire,
            validationNowMs,
            options
          );
          await recheck(initial, exactProposal);
          timeAndSyncCheck();
          return signedAttemptWire;
        } finally {
          provider = undefined;
          signedEvent = undefined;
        }
      } catch {
        deny();
      }
    }
  });
}
