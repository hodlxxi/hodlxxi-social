import { normalizePublicKey } from "./domain.mjs";
import { FULL_RECIPIENT_DIRECTORY_UNAVAILABLE, normalizeFullRecipientDirectory } from "./full-recipient-directory.mjs";

export const PUBLIC = "PUBLIC";
export const FULL_NETWORK = "FULL_NETWORK";

export const ProtectedAudience = Object.freeze({
  PUBLIC,
  FULL_NETWORK
});

const ALLOW_PUBLIC = Object.freeze({ allowed: true, reason: "public" });
const ALLOW_CURRENT_FULL = Object.freeze({ allowed: true, reason: "current-full" });
const DENY_AUDIENCE = Object.freeze({ allowed: false, reason: "unsupported-audience" });
const DENY_AUTHORITY = Object.freeze({ allowed: false, reason: "authority-required" });

export const PROTECTED_READ_DENIED = Object.freeze({ state: "denied", items: Object.freeze([]) });

const recordSnapshot = (value, required, optional = []) => {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const fields = Reflect.ownKeys(descriptors);
    if (!fields.every((field) => typeof field === "string" && (required.includes(field) || optional.includes(field)))) return undefined;
    if (!required.every((field) => fields.includes(field))) return undefined;
    if (!fields.every((field) => descriptors[field].enumerable && Object.hasOwn(descriptors[field], "value"))) return undefined;
    return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
  } catch {
    return undefined;
  }
};

const canonicalSubject = (value) => {
  try {
    return typeof value === "string" && value === normalizePublicKey(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

const currentFullFor = (assertion, subject, now) => {
  const record = recordSnapshot(assertion, ["source", "version", "subject", "status", "expiresAt"], ["evidenceRef"]);
  if (!Number.isFinite(now) || !record) return false;
  if (record.source !== "hodlxxi-crt" || record.version !== 1 || record.status !== "full") return false;
  if (!Number.isFinite(record.expiresAt) || record.expiresAt <= now) return false;
  if (record.evidenceRef !== undefined && (typeof record.evidenceRef !== "string" || !record.evidenceRef.trim())) return false;
  return canonicalSubject(record.subject) === subject;
};

const decision = (input) => {
  const record = recordSnapshot(input, [], ["audience", "authenticatedSubject", "assertion", "now"]);
  if (!record) return DENY_AUDIENCE;
  const { audience, authenticatedSubject, assertion, now } = record;
  if (audience === ProtectedAudience.PUBLIC) return ALLOW_PUBLIC;
  if (audience !== ProtectedAudience.FULL_NETWORK) return DENY_AUDIENCE;
  const subject = canonicalSubject(authenticatedSubject);
  return subject && currentFullFor(assertion, subject, now) ? ALLOW_CURRENT_FULL : DENY_AUTHORITY;
};

export function protectedWriteDecision(input = {}) {
  return decision(input);
}

export function protectedReadDecision(input = {}) {
  return decision(input);
}

export function protectedReadResult(decisionValue, openedItems) {
  if (decisionValue !== ALLOW_CURRENT_FULL && decisionValue !== ALLOW_PUBLIC) return PROTECTED_READ_DENIED;
  if (!Array.isArray(openedItems)) return PROTECTED_READ_DENIED;
  return Object.freeze({ state: "available", items: Object.freeze([...openedItems]) });
}

export const MAX_PROTECTED_RECIPIENTS = 4096;
export const PROTECTED_ENVELOPE_SCHEMA = "hodlxxi.protected_envelope.v1";
export const PROTECTED_PAYLOAD_SCHEMA = "hodlxxi.protected_payload.v1";

export function normalizeCurrentFullRecipients(value, { now, limit = MAX_PROTECTED_RECIPIENTS } = {}) {
  if (!Array.isArray(value) || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PROTECTED_RECIPIENTS || value.length > limit) return undefined;
  const recipients = [];
  const seen = new Set();
  for (const assertion of value) {
    const record = recordSnapshot(assertion, ["source", "version", "subject", "status", "expiresAt"], ["evidenceRef"]);
    const subject = canonicalSubject(record?.subject);
    if (!subject || seen.has(subject) || !currentFullFor(assertion, subject, now)) return undefined;
    seen.add(subject);
    recipients.push(subject);
  }
  return Object.freeze(recipients.sort());
}

export function normalizeProtectedEnvelope(value) {
  const record = recordSnapshot(value, ["schema", "version", "opaquePayload"]);
  if (!record || record.schema !== PROTECTED_ENVELOPE_SCHEMA || record.version !== 1 || typeof record.opaquePayload !== "string" || !record.opaquePayload) return undefined;
  return Object.freeze(record);
}

export function normalizeProtectedPayload(value) {
  const record = recordSnapshot(value, ["schema", "version", "opaqueContent"]);
  if (!record || record.schema !== PROTECTED_PAYLOAD_SCHEMA || record.version !== 1 || typeof record.opaqueContent !== "string" || !record.opaqueContent) return undefined;
  return Object.freeze(record);
}

const protectedReference = (value) =>
  typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : undefined;

const recipientSubjects = (value) => {
  if (!Array.isArray(value) || value.length > MAX_PROTECTED_RECIPIENTS) return undefined;
  const subjects = [];
  const seen = new Set();
  for (const valueSubject of value) {
    const subject = canonicalSubject(valueSubject);
    if (!subject || seen.has(subject)) return undefined;
    seen.add(subject);
    subjects.push(subject);
  }
  return Object.freeze(subjects.sort());
};

export function defineProtectedContentDependencies(input = {}) {
  const dependencies = recordSnapshot(input, ["recipientResolver", "transport", "envelope"]);
  const recipientResolver = dependencies?.recipientResolver;
  const transport = dependencies?.transport;
  const envelope = dependencies?.envelope;
  const resolverRecord = recordSnapshot(recipientResolver, ["resolveDirectory"]);
  const transportRecord = recordSnapshot(transport, ["putEnvelope", "getEnvelope"]);
  const envelopeRecord = recordSnapshot(envelope, ["produceEnvelope", "openEnvelope"]);
  if (typeof resolverRecord?.resolveDirectory !== "function") throw new TypeError("protected recipient resolver required");
  if (typeof transportRecord?.putEnvelope !== "function" || typeof transportRecord?.getEnvelope !== "function") throw new TypeError("protected envelope transport required");
  if (typeof envelopeRecord?.produceEnvelope !== "function" || typeof envelopeRecord?.openEnvelope !== "function") throw new TypeError("protected envelope dependency required");
  const safeRecipientResolver = Object.freeze({
    async resolveDirectory(optionsValue) {
      const options = recordSnapshot(optionsValue, ["now", "limit"]);
      if (!options || !Number.isFinite(options.now) || !Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > MAX_PROTECTED_RECIPIENTS) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
      try {
        const snapshot = await resolverRecord.resolveDirectory(Object.freeze(options));
        return normalizeFullRecipientDirectory(snapshot, options);
      } catch {
        return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
      }
    }
  });
  const safeTransport = Object.freeze({
    async putEnvelope(referenceValue, envelopeValue) {
      const reference = protectedReference(referenceValue);
      const normalized = normalizeProtectedEnvelope(envelopeValue);
      if (!reference || !normalized) throw new TypeError("opaque protected envelope required");
      if (await transportRecord.putEnvelope(reference, normalized) !== true) throw new TypeError("protected envelope transport unavailable");
      return true;
    },
    async getEnvelope(referenceValue) {
      const reference = protectedReference(referenceValue);
      if (!reference) return undefined;
      try {
        return normalizeProtectedEnvelope(await transportRecord.getEnvelope(reference));
      } catch {
        return undefined;
      }
    }
  });
  const safeEnvelope = Object.freeze({
    async produceEnvelope(payloadValue, recipientValue) {
      const payload = normalizeProtectedPayload(payloadValue);
      const recipients = recipientSubjects(recipientValue);
      if (!payload || !recipients) throw new TypeError("opaque protected payload required");
      return normalizeProtectedEnvelope(await envelopeRecord.produceEnvelope(payload, recipients));
    },
    async openEnvelope(envelopeValue, subjectValue) {
      const normalized = normalizeProtectedEnvelope(envelopeValue);
      const subject = canonicalSubject(subjectValue);
      if (!normalized || !subject) return undefined;
      try {
        return normalizeProtectedPayload(await envelopeRecord.openEnvelope(normalized, subject));
      } catch {
        return undefined;
      }
    }
  });
  return Object.freeze({ recipientResolver: safeRecipientResolver, transport: safeTransport, envelope: safeEnvelope });
}

export async function resolveProtectedRecipients(dependencies, { now, limit = MAX_PROTECTED_RECIPIENTS } = {}) {
  try {
    return await dependencies.recipientResolver.resolveDirectory(Object.freeze({ now, limit }));
  } catch {
    return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
  }
}

export async function resolveFullRecipientDirectory(resolver, { now, limit = MAX_PROTECTED_RECIPIENTS } = {}) {
  if (!Number.isFinite(now) || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PROTECTED_RECIPIENTS) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
  try {
    const record = recordSnapshot(resolver, ["resolveDirectory"]);
    if (typeof record?.resolveDirectory !== "function") return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    const snapshot = await record.resolveDirectory(Object.freeze({ now, limit }));
    return normalizeFullRecipientDirectory(snapshot, { now, limit });
  } catch {
    return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
  }
}
