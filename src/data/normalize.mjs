import { AccessStatus, EdgeType, normalizePublicKey, participant, relationship } from "../domain.mjs";

const array = (value, label) => {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return value;
};
const text = (value, label, { empty = false } = {}) => {
  if (typeof value !== "string" || (!empty && !value.trim())) throw new TypeError(`${label} must be text`);
  return value;
};
const integer = (value, label) => {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a non-negative integer`);
  return value;
};
const key = (value) => normalizePublicKey(value);
const freezeList = (value, normalize, label) => Object.freeze(array(value, label).map(normalize));
const record = (value, allowed, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((field) => !allowed.includes(field))) throw new TypeError(`${label} must be a supported record`);
  return value;
};

export function normalizeParticipants(value) {
  const records = freezeList(value, (raw) => {
    record(raw, ["id", "publicKey", "displayName"], "participant");
    const domainRecord = participant({ publicKey: raw.publicKey ?? raw.id, displayName: text(raw.displayName, "participant display name") });
    if (raw.id !== undefined && key(raw.id) !== domainRecord.id) throw new TypeError("participant identity mismatch");
    return domainRecord;
  }, "participants");
  if (new Set(records.map(({ id }) => id)).size !== records.length) throw new TypeError("participant identities must be unique");
  return records;
}

export function normalizeRelationships(value) {
  return freezeList(value, (raw) => {
    record(raw, ["type", "from", "to"], "relationship");
    if (!Object.values(EdgeType).includes(raw.type)) throw new TypeError("unsupported relationship type");
    return relationship(raw.type, raw.from, raw.to);
  }, "relationships");
}

export function normalizeFeed(value) {
  return freezeList(value, (raw) => {
    record(raw, ["id", "authorId", "audience", "body", "timestamp", "reactions", "comments", "reposts", "media", "replies"], "feed record");
    if (!["PUBLIC", "FULL_NETWORK", "FRIENDS"].includes(raw.audience)) throw new TypeError("malformed feed record");
    const replies = freezeList(raw.replies ?? [], (reply) => { record(reply, ["id", "authorId", "body"], "reply"); return Object.freeze({ id: text(reply.id, "reply id"), authorId: key(reply.authorId), body: text(reply.body, "reply body") }); }, "replies");
    return Object.freeze({ id: text(raw.id, "post id"), authorId: key(raw.authorId), audience: raw.audience, body: text(raw.body, "post body"), timestamp: text(raw.timestamp, "post timestamp"), reactions: integer(raw.reactions, "post reactions"), comments: integer(raw.comments, "post comments"), reposts: integer(raw.reposts, "post reposts"), ...(raw.media === undefined ? {} : { media: text(raw.media, "post media") }), replies });
  }, "feed");
}

export function normalizeGroups(value) {
  return freezeList(value, (raw) => { record(raw, ["id", "title", "description", "memberIds", "activity"], "group"); return Object.freeze({ id: text(raw.id, "group id"), title: text(raw.title, "group title"), description: text(raw.description, "group description"), memberIds: freezeList(raw.memberIds, key, "group members"), activity: text(raw.activity, "group activity") }); }, "groups");
}

export function normalizeConversations(value) {
  return freezeList(value, (raw) => { record(raw, ["id", "memberIds", "unreadFor", "messages"], "conversation"); return Object.freeze({
    id: text(raw?.id, "conversation id"),
    memberIds: freezeList(raw?.memberIds, key, "conversation members"),
    unreadFor: freezeList(raw?.unreadFor, key, "conversation unread identities"),
    messages: freezeList(raw.messages, (message) => { record(message, ["authorId", "body", "timestamp"], "message"); return Object.freeze({ authorId: key(message.authorId), body: text(message.body, "message body"), timestamp: text(message.timestamp, "message timestamp") }); }, "messages")
  }); }, "conversations");
}

export function normalizeNotifications(value) {
  return freezeList(value, (raw) => {
    record(raw, ["id", "actorId", "kind", "action", "targetLabel", "timestamp", "unread", "target"], "notification");
    if (typeof raw.unread !== "boolean") throw new TypeError("notification unread must be boolean");
    if (!raw?.target || typeof raw.target !== "object" || !["home", "profile", "message", "group"].includes(raw.target.type)) throw new TypeError("malformed notification target");
    record(raw.target, ["type", "id"], "notification target");
    const target = Object.freeze({ type: raw.target.type, ...(raw.target.id === undefined ? {} : { id: text(raw.target.id, "notification target id") }) });
    return Object.freeze({ id: text(raw.id, "notification id"), actorId: key(raw.actorId), kind: text(raw.kind, "notification kind"), action: text(raw.action, "notification action"), targetLabel: text(raw.targetLabel, "notification target label"), timestamp: text(raw.timestamp, "notification timestamp"), unread: raw.unread, target });
  }, "notifications");
}

export function normalizeExternalAssertion(subjectValue, raw, now) {
  const subject = key(subjectValue);
  const supported = raw && typeof raw === "object" && !Array.isArray(raw) && Object.keys(raw).every((field) => ["source", "version", "subject", "status", "expiresAt", "evidenceRef"].includes(field));
  let matchingSubject = false;
  try { matchingSubject = supported && key(raw.subject) === subject; } catch {}
  const validEvidence = raw?.evidenceRef === undefined || (typeof raw.evidenceRef === "string" && Boolean(raw.evidenceRef.trim()));
  const valid = Boolean(supported && raw.source === "hodlxxi-crt" && raw.version === 1 && matchingSubject && Object.values(AccessStatus).includes(raw.status) && Number.isFinite(now) && Number.isFinite(raw.expiresAt) && raw.expiresAt > now && validEvidence);
  return Object.freeze({ subject, assertedStatus: valid ? raw.status : AccessStatus.LIMITED, source: valid ? raw.source : "unavailable", valid, ...(valid && raw.evidenceRef !== undefined ? { evidenceRef: raw.evidenceRef } : {}) });
}
