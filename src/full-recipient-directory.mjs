import { normalizePublicKey } from "./domain.mjs";
import { MAX_PROTECTED_RECIPIENTS } from "./protected-content.mjs";

export const FULL_RECIPIENT_DIRECTORY_SCHEMA = "hodlxxi.full_recipient_directory.v1";
export const FULL_RECIPIENT_DIRECTORY_SOURCE = "hodlxxi-crt";
export const FULL_RECIPIENT_ENCRYPTION_ALGORITHM = "x25519-v1";
export const MAX_FULL_DIRECTORY_FRESHNESS_MS = 5 * 60 * 1000;
export const FULL_RECIPIENT_DIRECTORY_UNAVAILABLE = Object.freeze({ state: "unavailable" });

const exactRecord = (value, fields) => {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || !fields.every((field) => keys.includes(field))) return undefined;
    if (!keys.every((key) => typeof key === "string" && fields.includes(key) && descriptors[key].enumerable && Object.hasOwn(descriptors[key], "value"))) return undefined;
    return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
  } catch {
    return undefined;
  }
};

const canonicalKey = (value) => {
  try {
    return typeof value === "string" && value === normalizePublicKey(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

const boundedId = (value) =>
  typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : undefined;

const PROHIBITED_X25519_KEYS = new Set([
  "00".repeat(32),
  `01${"00".repeat(31)}`,
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098c9d770ad86a4aa59bf9814b4d00",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  `ec${"ff".repeat(30)}7f`,
  `ed${"ff".repeat(30)}7f`,
  `ee${"ff".repeat(30)}7f`
]);

const denseDataArray = (value) => {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0) return undefined;
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== length + 1 || !keys.every((key) => key === "length" || (typeof key === "string" && /^(0|[1-9]\d*)$/.test(key)))) return undefined;
    const items = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) return undefined;
      items.push(descriptor.value);
    }
    return items;
  } catch {
    return undefined;
  }
};

const normalizeRecipient = (value, snapshot, now) => {
  const recipient = exactRecord(value, ["snapshotId", "subject", "encryptionKey", "authority"]);
  const key = exactRecord(recipient?.encryptionKey, ["algorithm", "version", "publicKey", "validFrom", "expiresAt", "revoked"]);
  const authority = exactRecord(recipient?.authority, ["source", "version", "snapshotId", "subject", "status", "expiresAt"]);
  const subject = canonicalKey(recipient?.subject);
  const publicKey = canonicalKey(key?.publicKey);
  if (!recipient || !key || !authority || recipient.snapshotId !== snapshot.snapshotId) return undefined;
  if (!subject || !publicKey || publicKey === subject || (Number.parseInt(publicKey.slice(62), 16) & 0x80) !== 0 || PROHIBITED_X25519_KEYS.has(publicKey)) return undefined;
  if (key.algorithm !== FULL_RECIPIENT_ENCRYPTION_ALGORITHM || !Number.isSafeInteger(key.version) || key.version < 1 || key.revoked !== false) return undefined;
  if (!Number.isFinite(key.validFrom) || !Number.isFinite(key.expiresAt) || key.validFrom > now || key.expiresAt <= now || key.validFrom >= key.expiresAt) return undefined;
  if (key.validFrom < snapshot.issuedAt || key.expiresAt > snapshot.expiresAt) return undefined;
  if (authority.source !== FULL_RECIPIENT_DIRECTORY_SOURCE || authority.version !== 1 || authority.snapshotId !== snapshot.snapshotId) return undefined;
  if (authority.subject !== subject || canonicalKey(authority.subject) !== subject || authority.status !== "full") return undefined;
  if (!Number.isFinite(authority.expiresAt) || authority.expiresAt <= now || authority.expiresAt > snapshot.expiresAt) return undefined;
  return Object.freeze({
    subject,
    encryptionKey: Object.freeze({
      algorithm: key.algorithm,
      version: key.version,
      publicKey,
      validFrom: key.validFrom,
      expiresAt: key.expiresAt
    })
  });
};

export function normalizeFullRecipientDirectory(value, { now, limit = MAX_PROTECTED_RECIPIENTS } = {}) {
  try {
    const snapshot = exactRecord(value, ["schema", "version", "source", "snapshotId", "complete", "issuedAt", "expiresAt", "recipients"]);
    if (!snapshot || snapshot.schema !== FULL_RECIPIENT_DIRECTORY_SCHEMA || snapshot.version !== 1) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    if (snapshot.source !== FULL_RECIPIENT_DIRECTORY_SOURCE || !boundedId(snapshot.snapshotId) || snapshot.complete !== true) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    if (!Number.isFinite(now) || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PROTECTED_RECIPIENTS) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    if (!Number.isFinite(snapshot.issuedAt) || !Number.isFinite(snapshot.expiresAt) || snapshot.issuedAt > now || snapshot.expiresAt <= now) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    if (snapshot.expiresAt <= snapshot.issuedAt || snapshot.expiresAt - snapshot.issuedAt > MAX_FULL_DIRECTORY_FRESHNESS_MS) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    const rawRecipients = denseDataArray(snapshot.recipients);
    if (!rawRecipients || rawRecipients.length > limit) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
    const recipients = [];
    const subjects = new Set();
    const bindings = new Set();
    let previousSubject;
    for (const rawRecipient of rawRecipients) {
      const recipient = normalizeRecipient(rawRecipient, snapshot, now);
      if (!recipient || subjects.has(recipient.subject)) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
      const binding = recipient.encryptionKey.publicKey;
      if (bindings.has(binding) || (previousSubject !== undefined && recipient.subject <= previousSubject)) return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
      subjects.add(recipient.subject);
      bindings.add(binding);
      previousSubject = recipient.subject;
      recipients.push(recipient);
    }
    return Object.freeze({ state: "available", snapshotId: snapshot.snapshotId, recipients: Object.freeze(recipients) });
  } catch {
    return FULL_RECIPIENT_DIRECTORY_UNAVAILABLE;
  }
}
