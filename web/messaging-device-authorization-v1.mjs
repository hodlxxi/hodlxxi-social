import {
  computeNostrEventId,
  verifyNostrEvent
} from "./nostr-event-verifier.mjs?v=1.28.1";

export const MESSAGING_DEVICE_AUTHORIZATION_INTENT_ROUTE =
  "/auth/messaging-device-binding-authorization-intents";
export const MESSAGING_DEVICE_AUTHORIZATION_ROUTE =
  "/auth/messaging-device-binding-authorizations";
export const MESSAGING_DEVICE_INTENT_HEADER =
  "X-HODLXXI-Device-Binding-Intent";
export const MESSAGING_DEVICE_SIGNATURE_FORMAT =
  "nostr_event_id_bip340_v1";
export const MESSAGING_DEVICE_EVENT_KIND = 27236;
export const MESSAGING_DEVICE_EVENT_PURPOSE =
  "hodlxxi-social-messaging-device-binding-authorization-v1";

const INTENT_SCHEMA =
  "hodlxxi.social_messaging_device_binding_authorization_intent.v1";
const AUTHORIZATION_SCHEMA =
  "hodlxxi.social_messaging_device_binding_authorization.v1";
const AUTHORIZATION_RESULT_SCHEMA =
  "hodlxxi.social_messaging_device_binding_authorization_result.v1";
const AUTHORIZATION_RETRY_SCHEMA =
  "hodlxxi.social_messaging_device_binding_authorization_retry.v1";
const ADOPTION_SCHEMA =
  "hodlxxi.social_messaging_device_binding_adoption.v1";
const BINDING_SCHEMA =
  "hodlxxi.social_messaging_device_binding_record.v1";
const AUTHORIZATION_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1";
const ADOPTION_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_ADOPTION_V1";
const INTENT_TOKEN_TYPE = "hodlxxi-device-binding-intent+jwt";
const INTENT_TOKEN_USE = "device_binding_authorization_intent";
const INTENT_TOKEN_PURPOSE =
  "social_messaging_device_binding_authorization_intent_v1";
const INTENT_TOKEN_AUDIENCE =
  "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1";
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_INTENT_BYTES = 32 * 1024;
const MAX_RESULT_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;

const failureKinds = new WeakMap();
const unavailable = (kind = "malformed") => {
  const error = new TypeError("messaging device authorization unavailable");
  failureKinds.set(error, kind);
  throw error;
};

export const messagingDeviceAuthorizationFailureKind = (error) =>
  failureKinds.get(error) ?? "malformed";

const ownPlain = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const exact = (value, fields) => {
  if (!ownPlain(value)) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    keys.some((key) =>
      typeof key !== "string" ||
      !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    ) ||
    fields.some((field) => !Object.hasOwn(descriptors, field))
  ) unavailable();
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
};

const stableValue = (value) => {
  if (Array.isArray(value)) return value.map(stableValue);
  if (ownPlain(value)) {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, stableValue(value[key])])
    );
  }
  return value;
};

export const canonicalMessagingDeviceJson = (value) => {
  try {
    const encoded = JSON.stringify(stableValue(value));
    if (
      typeof encoded !== "string" ||
      encoded.length === 0 ||
      /[^\x20-\x7e]/.test(encoded)
    ) unavailable();
    return encoded;
  } catch {
    unavailable();
  }
};

const canonicalParsedJson = (source, maximum) => {
  if (
    typeof source !== "string" ||
    source.length === 0 ||
    new TextEncoder().encode(source).byteLength > maximum ||
    /[^\x20-\x7e]/.test(source)
  ) unavailable();
  let value;
  try { value = JSON.parse(source); } catch { unavailable(); }
  if (canonicalMessagingDeviceJson(value) !== source) unavailable();
  return value;
};

const utcSecond = (value) => {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) unavailable();
  const milliseconds = Date.parse(value);
  if (
    !Number.isSafeInteger(milliseconds) ||
    new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")
  ) unavailable();
  return milliseconds / 1000;
};

const exactTags = (value, digest, requestId, action) => {
  const expected = [
    ["purpose", MESSAGING_DEVICE_EVENT_PURPOSE],
    ["semantic-digest", digest],
    ["request-id", requestId],
    ["action", action]
  ];
  if (
    !Array.isArray(value) ||
    value.length !== expected.length ||
    value.some((tag, index) =>
      !Array.isArray(tag) ||
      tag.length !== 2 ||
      tag[0] !== expected[index][0] ||
      tag[1] !== expected[index][1]
    )
  ) unavailable();
  return Object.freeze(expected.map((tag) => Object.freeze([...tag])));
};

const lifecycleFields = [
  "algorithm", "bindingExpiresAt", "bindingRecordSchema",
  "bindingRecordVersion", "bindingValidFrom", "bindingVersion", "deviceId",
  "expiresAt", "issuedAt", "operation", "priorBindingId", "publicKey",
  "requestId", "schema", "subject", "version"
];
const bindingFields = [
  "algorithm", "bindingVersion", "deviceId", "expiresAt", "operation",
  "priorBindingId", "publicKey", "requestId", "schema", "subject",
  "validFrom", "version"
];
const adoptionFields = [
  "action", "bindingId", "bindingRecord", "expiresAt", "issuedAt",
  "requestId", "schema", "version"
];

const validateBindingRecord = (value) => {
  const record = exact(value, bindingFields);
  if (
    record.schema !== BINDING_SCHEMA || record.version !== 1 ||
    record.algorithm !== "x25519-v1" ||
    !["register", "rotate"].includes(record.operation) ||
    !HEX64.test(record.subject) || !HEX64.test(record.deviceId) ||
    !HEX64.test(record.publicKey) || record.publicKey === record.subject ||
    !Number.isSafeInteger(record.bindingVersion) || record.bindingVersion < 1 ||
    (record.operation === "register" ? record.priorBindingId !== null : !HEX64.test(record.priorBindingId)) ||
    !HEX64.test(record.requestId) ||
    utcSecond(record.validFrom) >= utcSecond(record.expiresAt)
  ) unavailable();
  return record;
};

const semanticClaim = (content, claimType, expectedPubkey) => {
  const envelope = canonicalParsedJson(content, 8192);
  if (claimType === "lifecycle") {
    const root = exact(envelope, ["authorization", "domain"]);
    const claim = exact(root.authorization, lifecycleFields);
    if (
      root.domain !== AUTHORIZATION_DOMAIN || claim.schema !== AUTHORIZATION_SCHEMA ||
      claim.version !== 1 || claim.bindingRecordSchema !== BINDING_SCHEMA ||
      claim.bindingRecordVersion !== 1 || !["register", "rotate", "revoke"].includes(claim.operation) ||
      claim.subject !== expectedPubkey || !HEX64.test(claim.deviceId) ||
      claim.algorithm !== "x25519-v1" || !HEX64.test(claim.publicKey) ||
      claim.publicKey === claim.subject || !Number.isSafeInteger(claim.bindingVersion) ||
      claim.bindingVersion < 1 ||
      (claim.operation === "register"
        ? claim.bindingVersion !== 1 || claim.priorBindingId !== null
        : claim.bindingVersion < 2 || !HEX64.test(claim.priorBindingId)) ||
      !HEX64.test(claim.requestId) ||
      utcSecond(claim.bindingValidFrom) !== utcSecond(claim.issuedAt) ||
      utcSecond(claim.issuedAt) >= utcSecond(claim.expiresAt) ||
      utcSecond(claim.expiresAt) > utcSecond(claim.bindingExpiresAt)
    ) unavailable();
    return Object.freeze({ claim, requestId: claim.requestId, action: claim.operation,
      issuedAt: utcSecond(claim.issuedAt), expiresAt: utcSecond(claim.expiresAt) });
  }
  if (claimType !== "adoption") unavailable();
  const root = exact(envelope, ["adoption", "domain"]);
  const claim = exact(root.adoption, adoptionFields);
  const binding = validateBindingRecord(claim.bindingRecord);
  if (
    root.domain !== ADOPTION_DOMAIN || claim.schema !== ADOPTION_SCHEMA ||
    claim.version !== 1 || claim.action !== "adopt" ||
    !HEX64.test(claim.bindingId) || !HEX64.test(claim.requestId) ||
    claim.requestId === binding.requestId || binding.subject !== expectedPubkey ||
    utcSecond(claim.issuedAt) >= utcSecond(claim.expiresAt) ||
    utcSecond(claim.expiresAt) > utcSecond(binding.expiresAt)
  ) unavailable();
  return Object.freeze({ claim, requestId: claim.requestId, action: "adopt",
    issuedAt: utcSecond(claim.issuedAt), expiresAt: utcSecond(claim.expiresAt) });
};

const base64urlObject = (token, index) => {
  try {
    const segment = token.split(".")[index];
    const source = segment.replace(/-/g, "+").replace(/_/g, "/");
    const bytes = Uint8Array.from(atob(source + "=".repeat((4 - source.length % 4) % 4)),
      (character) => character.charCodeAt(0));
    const text = new TextDecoder("ascii", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch {
    unavailable();
  }
};

const tokenIdentity = (token) => {
  if (typeof token !== "string" || token.length > 16 * 1024 || !JWT.test(token)) unavailable();
  const header = exact(base64urlObject(token, 0), ["alg", "kid", "typ"]);
  const claims = exact(base64urlObject(token, 1), [
    "action", "aud", "claimType", "digest", "eventId", "exp", "iat", "iss",
    "jti", "purpose", "signatureFormat", "sub", "tokenUse"
  ]);
  if (
    header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid ||
    header.typ !== INTENT_TOKEN_TYPE || typeof claims.iss !== "string" || !claims.iss ||
    claims.aud !== INTENT_TOKEN_AUDIENCE || claims.tokenUse !== INTENT_TOKEN_USE ||
    claims.purpose !== INTENT_TOKEN_PURPOSE || !["lifecycle", "adoption"].includes(claims.claimType) ||
    !["register", "rotate", "revoke", "adopt"].includes(claims.action) ||
    !HEX64.test(claims.digest) || !HEX64.test(claims.eventId) ||
    !HEX64.test(claims.jti) || !HEX64.test(claims.sub) ||
    claims.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT ||
    !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
    claims.exp <= claims.iat || claims.exp - claims.iat > 300
  ) unavailable();
  return Object.freeze({ token, claims });
};

const digestHex = async (value, cryptoImpl) => {
  if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.digest !== "function") unavailable();
  const result = await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, "0")).join("");
};

const bindingIdentity = async (semantic, subject, cryptoImpl) => {
  const binding = semantic.action === "adopt"
    ? semantic.claim.bindingRecord
    : {
        algorithm: semantic.claim.algorithm,
        bindingVersion: semantic.claim.bindingVersion,
        deviceId: semantic.claim.deviceId,
        expiresAt: semantic.claim.bindingExpiresAt,
        operation: semantic.claim.operation,
        priorBindingId: semantic.claim.priorBindingId,
        publicKey: semantic.claim.publicKey,
        requestId: semantic.claim.requestId,
        schema: semantic.claim.bindingRecordSchema,
        subject,
        validFrom: semantic.claim.bindingValidFrom,
        version: semantic.claim.bindingRecordVersion
      };
  const bindingId = await digestHex(canonicalMessagingDeviceJson(binding), cryptoImpl);
  if (semantic.action === "adopt" && semantic.claim.bindingId !== bindingId) unavailable();
  return Object.freeze({ binding: Object.freeze(stableValue(binding)), bindingId });
};

const proposalValue = (value) =>
  canonicalParsedJson(canonicalMessagingDeviceAuthorizationProposal(value), 1024);

const bindSemanticToProposal = async (semantic, value, subject, cryptoImpl) => {
  const proposal = proposalValue(value);
  if (proposal.operation === "adopt") {
    if (
      semantic.action !== "adopt" || semantic.claim.action !== "adopt" ||
      semantic.requestId !== proposal.requestId ||
      semantic.claim.bindingId !== proposal.bindingId
    ) unavailable();
  } else {
    const claim = semantic.claim;
    if (
      semantic.action !== proposal.operation || claim.operation !== proposal.operation ||
      claim.requestId !== proposal.requestId || claim.deviceId !== proposal.deviceId
    ) unavailable();
    if (proposal.operation === "register") {
      if (
        claim.publicKey !== proposal.publicKey || claim.priorBindingId !== null ||
        claim.bindingVersion !== 1 || proposal.expectedBindingId !== null
      ) unavailable();
    } else if (proposal.operation === "rotate") {
      if (
        claim.publicKey !== proposal.publicKey ||
        claim.priorBindingId !== proposal.expectedBindingId
      ) unavailable();
    } else if (
      proposal.operation !== "revoke" ||
      claim.priorBindingId !== proposal.expectedBindingId
    ) unavailable();
  }
  const identity = await bindingIdentity(semantic, subject, cryptoImpl);
  return Object.freeze({ proposal: Object.freeze(proposal), ...identity });
};

const expectedEventId = (subject, unsignedEvent, cryptoImpl) =>
  computeNostrEventId({
    content: unsignedEvent.content,
    created_at: unsignedEvent.created_at,
    id: "0".repeat(64),
    kind: unsignedEvent.kind,
    pubkey: subject,
    sig: "0".repeat(128),
    tags: unsignedEvent.tags
  }, { cryptoImpl });

export async function parseMessagingDeviceAuthorizationIntent(
  value,
  { subject, proposal, cryptoImpl = globalThis.crypto, now = Date.now } = {}
) {
  const intent = exact(value, [
    "claim", "claimType", "digest", "expectedPubkey", "intentToken", "schema",
    "signatureFormat", "unsignedEvent", "version"
  ]);
  if (
    intent.schema !== INTENT_SCHEMA || intent.version !== 1 ||
    !["lifecycle", "adoption"].includes(intent.claimType) ||
    !HEX64.test(subject) || intent.expectedPubkey !== subject ||
    !HEX64.test(intent.digest) ||
    intent.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT
  ) unavailable();
  const unsigned = exact(intent.unsignedEvent, ["content", "created_at", "kind", "tags"]);
  const semantic = semanticClaim(unsigned.content, intent.claimType, subject);
  if (
    canonicalMessagingDeviceJson(intent.claim) !== canonicalMessagingDeviceJson(semantic.claim) ||
    unsigned.kind !== MESSAGING_DEVICE_EVENT_KIND ||
    unsigned.created_at !== semantic.issuedAt ||
    await digestHex(unsigned.content, cryptoImpl) !== intent.digest
  ) unavailable();
  const tags = exactTags(unsigned.tags, intent.digest, semantic.requestId, semantic.action);
  const frozenUnsigned = Object.freeze({
    content: unsigned.content,
    created_at: unsigned.created_at,
    kind: unsigned.kind,
    tags
  });
  const identity = proposal === undefined
    ? await bindingIdentity(semantic, subject, cryptoImpl)
    : await bindSemanticToProposal(semantic, proposal, subject, cryptoImpl);
  const eventId = await expectedEventId(subject, frozenUnsigned, cryptoImpl);
  const token = tokenIdentity(intent.intentToken);
  const claims = token.claims;
  const current = typeof now === "function" ? Math.floor(now() / 1000) : NaN;
  if (
    !Number.isSafeInteger(current) || claims.iat > current || current >= claims.exp ||
    claims.sub !== subject || claims.iat !== semantic.issuedAt ||
    claims.exp !== semantic.expiresAt || claims.jti !== semantic.requestId ||
    claims.claimType !== intent.claimType || claims.action !== semantic.action ||
    claims.digest !== intent.digest || claims.eventId !== eventId
  ) unavailable();
  return Object.freeze({
    claim: Object.freeze(stableValue(semantic.claim)),
    claimType: intent.claimType,
    digest: intent.digest,
    expectedPubkey: subject,
    intentToken: token.token,
    signatureFormat: MESSAGING_DEVICE_SIGNATURE_FORMAT,
    unsignedEvent: frozenUnsigned,
    eventId,
    action: semantic.action,
    requestId: semantic.requestId,
    binding: identity.binding,
    bindingId: identity.bindingId
  });
}

const sameTags = (left, right) =>
  Array.isArray(left) && left.length === right.length &&
  left.every((tag, index) => Array.isArray(tag) && tag.length === right[index].length &&
    tag.every((item, itemIndex) => item === right[index][itemIndex]));

export async function signMessagingDeviceAuthorizationIntent(
  { subject, proposal, intent } = {},
  { signer, cryptoImpl = globalThis.crypto, verifyEvent = verifyNostrEvent, now = Date.now } = {}
) {
  if (typeof verifyEvent !== "function") unavailable();
  const checked = await parseMessagingDeviceAuthorizationIntent(
    intent,
    { subject, proposal, cryptoImpl, now }
  );
  if (!signer || typeof signer.signEventForSubject !== "function") unavailable();
  let candidate;
  try {
    candidate = await signer.signEventForSubject({
      subject,
      unsignedEvent: checked.unsignedEvent
    });
  } catch {
    unavailable("ambiguous");
  }
  let verified;
  try { verified = await verifyEvent(candidate, { cryptoImpl }); } catch { unavailable(); }
  if (
    verified.pubkey !== subject || verified.id !== checked.eventId ||
    verified.kind !== checked.unsignedEvent.kind ||
    verified.created_at !== checked.unsignedEvent.created_at ||
    verified.content !== checked.unsignedEvent.content ||
    !sameTags(verified.tags, checked.unsignedEvent.tags) || !HEX128.test(verified.sig)
  ) unavailable();
  return Object.freeze({
    intentToken: checked.intentToken,
    signedEvent: verified,
    action: checked.action,
    requestId: checked.requestId
  });
}

export async function composeMessagingDeviceAuthorizationPayload(
  { subject, intentToken, signedEvent } = {},
  {
    cryptoImpl = globalThis.crypto,
    verifyEvent = verifyNostrEvent,
    now = Date.now,
    allowExpiredExactReplay = false
  } = {}
) {
  if (!HEX64.test(subject) || typeof verifyEvent !== "function" ||
      typeof allowExpiredExactReplay !== "boolean") unavailable();
  const token = tokenIdentity(intentToken);
  let verified;
  try { verified = await verifyEvent(signedEvent, { cryptoImpl }); } catch { unavailable(); }
  const claims = token.claims;
  const current = typeof now === "function" ? Math.floor(now() / 1000) : NaN;
  const semantic = semanticClaim(verified.content, claims.claimType, subject);
  const digest = await digestHex(verified.content, cryptoImpl);
  exactTags(verified.tags, digest, semantic.requestId, semantic.action);
  if (
    !Number.isSafeInteger(current) || claims.iat > current ||
    (!allowExpiredExactReplay && current >= claims.exp) ||
    verified.pubkey !== subject || verified.kind !== MESSAGING_DEVICE_EVENT_KIND ||
    verified.created_at !== semantic.issuedAt || claims.sub !== subject ||
    claims.iat !== semantic.issuedAt || claims.exp !== semantic.expiresAt ||
    claims.jti !== semantic.requestId || claims.action !== semantic.action ||
    claims.digest !== digest || claims.eventId !== verified.id ||
    claims.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT
  ) unavailable();
  return canonicalMessagingDeviceJson({
    ...semantic.claim,
    digest,
    signature: verified.sig,
    signatureFormat: MESSAGING_DEVICE_SIGNATURE_FORMAT
  });
}

export async function parseMessagingDeviceAuthorizationResult(
  value,
  { subject, proposal, intentToken, signedEvent } = {},
  {
    cryptoImpl = globalThis.crypto,
    verifyEvent = verifyNostrEvent,
    now = Date.now,
    allowExpiredExactReplay = false
  } = {}
) {
  if (typeof allowExpiredExactReplay !== "boolean") unavailable();
  await composeMessagingDeviceAuthorizationPayload(
    { subject, intentToken, signedEvent },
    { cryptoImpl, verifyEvent, now, allowExpiredExactReplay }
  );
  const verified = await verifyEvent(signedEvent, { cryptoImpl });
  const token = tokenIdentity(intentToken);
  const semantic = semanticClaim(verified.content, token.claims.claimType, subject);
  const { binding, bindingId } = proposal === undefined
    ? await bindingIdentity(semantic, subject, cryptoImpl)
    : await bindSemanticToProposal(semantic, proposal, subject, cryptoImpl);
  const result = exact(value, [
    "action", "active", "authorizationExpiresAt", "authorizationProofId",
    "authorizationValidFrom", "bindingId", "bindingOperation", "bindingVersion",
    "deviceId", "expiresAt", "requestId", "schema", "validFrom", "version"
  ]);
  if (
    result.schema !== AUTHORIZATION_RESULT_SCHEMA || result.version !== 1 ||
    result.action !== semantic.action || result.active !== (binding.operation !== "revoke") ||
    result.authorizationExpiresAt !== binding.expiresAt ||
    result.authorizationProofId !==
      `hodlxxi-binding-authorization-v1-sha256:${token.claims.digest}` ||
    result.authorizationValidFrom !== semantic.claim.issuedAt ||
    result.bindingId !== bindingId || result.bindingOperation !== binding.operation ||
    result.bindingVersion !== binding.bindingVersion || result.deviceId !== binding.deviceId ||
    result.expiresAt !== binding.expiresAt || result.requestId !== semantic.requestId ||
    result.validFrom !== binding.validFrom
  ) unavailable();
  return Object.freeze(result);
}

const boundedResponse = async (response, maximum) => {
  if (response?.status !== 200) {
    if (Number.isInteger(response?.status) &&
        response.status >= 500 && response.status <= 599) unavailable("ambiguous");
    if (Number.isInteger(response?.status) &&
        response.status >= 400 && response.status <= 499) unavailable("rejected");
    unavailable();
  }
  if (
    typeof response.text !== "function" ||
    !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(
      response.headers?.get?.("content-type") ?? ""
    )
  ) unavailable();
  let body;
  try { body = await response.text(); }
  catch { unavailable("ambiguous"); }
  return canonicalParsedJson(body, maximum);
};

export function canonicalMessagingDeviceAuthorizationProposal(value) {
  const operation = value?.operation;
  const fields = operation === "adopt"
    ? ["bindingId", "operation", "requestId"]
    : ["deviceId", "expectedBindingId", "operation", "publicKey", "requestId"];
  const proposal = exact(value, fields);
  if (operation === "adopt") {
    if (!HEX64.test(proposal.bindingId) || !HEX64.test(proposal.requestId)) unavailable();
  } else if (
    !["register", "rotate", "revoke"].includes(operation) ||
    !HEX64.test(proposal.deviceId) || !HEX64.test(proposal.requestId) ||
    (operation === "register" ? proposal.expectedBindingId !== null : !HEX64.test(proposal.expectedBindingId)) ||
    (operation === "revoke" ? proposal.publicKey !== null : !HEX64.test(proposal.publicKey))
  ) unavailable();
  return canonicalMessagingDeviceJson(proposal);
}

export async function parseMessagingDeviceAuthorizationRetry(
  value,
  { subject, proposal } = {},
  {
    cryptoImpl = globalThis.crypto,
    verifyEvent = verifyNostrEvent,
    now = Date.now,
    allowExpiredExactReplay = false
  } = {}
) {
  if (typeof allowExpiredExactReplay !== "boolean") unavailable();
  const retry = exact(value, [
    "intentToken", "proposal", "schema", "signedEvent", "subject", "version"
  ]);
  const proposalBody = canonicalMessagingDeviceAuthorizationProposal(proposal);
  if (
    retry.schema !== AUTHORIZATION_RETRY_SCHEMA || retry.version !== 1 ||
    retry.subject !== subject || retry.proposal !== proposalBody ||
    !HEX64.test(subject) || typeof verifyEvent !== "function"
  ) unavailable();
  const token = tokenIdentity(retry.intentToken);
  let verified;
  try { verified = await verifyEvent(retry.signedEvent, { cryptoImpl }); }
  catch { unavailable(); }
  const semantic = semanticClaim(verified.content, token.claims.claimType, subject);
  const digest = await digestHex(verified.content, cryptoImpl);
  const { binding, bindingId } = await bindSemanticToProposal(
    semantic,
    proposal,
    subject,
    cryptoImpl
  );
  exactTags(verified.tags, digest, semantic.requestId, semantic.action);
  const claims = token.claims;
  const current = typeof now === "function" ? Math.floor(now() / 1000) : NaN;
  if (
    !Number.isSafeInteger(current) || claims.iat > current ||
    (!allowExpiredExactReplay && current >= claims.exp) ||
    verified.pubkey !== subject || verified.kind !== MESSAGING_DEVICE_EVENT_KIND ||
    verified.created_at !== semantic.issuedAt || claims.sub !== subject ||
    claims.iat !== semantic.issuedAt || claims.exp !== semantic.expiresAt ||
    claims.jti !== semantic.requestId || claims.action !== semantic.action ||
    claims.digest !== digest ||
    claims.eventId !== verified.id ||
    claims.signatureFormat !== MESSAGING_DEVICE_SIGNATURE_FORMAT
  ) unavailable();
  return Object.freeze({
    action: semantic.action,
    binding,
    bindingId,
    digest,
    expiresAt: claims.exp,
    intentToken: retry.intentToken,
    proofId: `hodlxxi-binding-authorization-v1-sha256:${digest}`,
    proposal: Object.freeze(proposalValue(proposal)),
    requestId: semantic.requestId,
    signedEvent: verified
  });
}

export async function authorizeMessagingDeviceBinding(
  { subject, proposal, pendingAuthorization, expiredPendingAuthorization } = {},
  {
    signer,
    persistPending,
    fetchImpl = globalThis.fetch,
    cryptoImpl = globalThis.crypto,
    now = Date.now,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    setTimer = globalThis.setTimeout,
    clearTimer = globalThis.clearTimeout,
    signal
  } = {}
) {
  if (
    !HEX64.test(subject) || typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 ||
    typeof setTimer !== "function" || typeof clearTimer !== "function" ||
    (signal !== undefined && (
      signal === null || typeof signal !== "object" ||
      typeof signal.addEventListener !== "function" ||
      typeof signal.removeEventListener !== "function"
    )) || (pendingAuthorization !== undefined && expiredPendingAuthorization !== undefined)
  ) unavailable();
  if (signal?.aborted === true) unavailable("ambiguous");
  const fetchOnce = async (url, init) => {
    const controller = new AbortController();
    const timer = setTimer(() => controller.abort(), timeoutMs);
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    try { return await fetchImpl(url, { ...init, signal: controller.signal }); }
    catch { unavailable("ambiguous"); }
    finally {
      clearTimer(timer);
      signal?.removeEventListener("abort", abort);
    }
  };
  const proposalBody = canonicalMessagingDeviceAuthorizationProposal(proposal);
  const allowExpiredExactReplay = expiredPendingAuthorization !== undefined;
  let retry = allowExpiredExactReplay ? expiredPendingAuthorization : pendingAuthorization;
  if (retry === undefined) {
    if (typeof persistPending !== "function") unavailable();
    const intentResponse = await fetchOnce(MESSAGING_DEVICE_AUTHORIZATION_INTENT_ROUTE, {
      method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: proposalBody
    });
    const intent = await boundedResponse(intentResponse, MAX_INTENT_BYTES);
    if (signal?.aborted === true) unavailable("ambiguous");
    const signed = await signMessagingDeviceAuthorizationIntent(
      { subject, proposal, intent }, { signer, cryptoImpl, now }
    );
    retry = Object.freeze({
      intentToken: signed.intentToken,
      proposal: proposalBody,
      schema: AUTHORIZATION_RETRY_SCHEMA,
      signedEvent: signed.signedEvent,
      subject,
      version: 1
    });
    try { await persistPending(retry); } catch { unavailable(); }
  }
  const checkedRetry = await parseMessagingDeviceAuthorizationRetry(
    retry,
    { subject, proposal },
    { cryptoImpl, now, allowExpiredExactReplay }
  );
  if (signal?.aborted === true) unavailable("ambiguous");
  const resultResponse = await fetchOnce(MESSAGING_DEVICE_AUTHORIZATION_ROUTE, {
    method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      [MESSAGING_DEVICE_INTENT_HEADER]: checkedRetry.intentToken
    },
    body: canonicalMessagingDeviceJson(checkedRetry.signedEvent)
  });
  return parseMessagingDeviceAuthorizationResult(
    await boundedResponse(resultResponse, MAX_RESULT_BYTES),
    {
      subject,
      proposal,
      intentToken: checkedRetry.intentToken,
      signedEvent: checkedRetry.signedEvent
    },
    { cryptoImpl, now, allowExpiredExactReplay }
  );
}

export function createNip07MessagingDeviceSigner({
  resolveProvider,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout
} = {}) {
  if (
    typeof resolveProvider !== "function" || typeof setTimer !== "function" ||
    typeof clearTimer !== "function" || !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 || timeoutMs > 30_000
  ) unavailable();
  const call = async (provider, method, args) => {
    let timer;
    try {
      const pending = method.call(provider, ...args);
      let owned;
      if (
        (typeof pending === "object" && pending !== null) ||
        typeof pending === "function"
      ) {
        try { owned = Promise.prototype.then.call(pending, (result) => result); }
        catch { unavailable(); }
      } else {
        owned = Promise.resolve(pending);
      }
      return await Promise.race([
        owned,
        new Promise((_, reject) => {
          timer = setTimer(() => reject(new TypeError("signer timeout")), timeoutMs);
        })
      ]);
    } finally {
      if (timer !== undefined) clearTimer(timer);
    }
  };
  return Object.freeze({
    async signEventForSubject({ subject, unsignedEvent } = {}) {
      let provider;
      try {
        provider = resolveProvider();
        if (!ownPlain(provider)) unavailable();
        const getPublicKey = Object.getOwnPropertyDescriptor(provider, "getPublicKey")?.value;
        if (typeof getPublicKey !== "function") unavailable();
        const publicKey = await call(provider, getPublicKey, []);
        if (!HEX64.test(publicKey) || publicKey !== subject) unavailable();
        const signEvent = Object.getOwnPropertyDescriptor(provider, "signEvent")?.value;
        if (typeof signEvent !== "function") unavailable();
        return await call(provider, signEvent, [unsignedEvent]);
      } catch {
        unavailable();
      } finally {
        provider = undefined;
      }
    }
  });
}
