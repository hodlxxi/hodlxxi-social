import { normalizePublicKey, participant } from "./domain.mjs";

const PUBLIC_RELAY_FILTER_FIELDS = Object.freeze(["ids", "authors", "kinds", "since", "until", "limit", "#e", "#p"]);
const PUBLIC_RELAY_FILTER_FIELD_SET = new Set(PUBLIC_RELAY_FILTER_FIELDS);
const HEX_PREFIX = /^[0-9a-fA-F]{1,64}$/;
const MAX_RELAY_FILTER_LIMIT = 500;

export function mapProfileEvent(event) {
  const validated = validatePublicEvent(event, { signed: true });
  if (validated.kind !== 0) throw new TypeError("unsupported Nostr profile event");
  let content;
  try { content = JSON.parse(validated.content); } catch { throw new TypeError("profile content must be JSON"); }
  return participant({ publicKey: validated.pubkey, displayName: content.display_name || content.name || "Participant" });
}

export function mapNoteEvent(event) {
  const validated = validatePublicEvent(event, { signed: true });
  if (validated.kind !== 1) throw new TypeError("unsupported Nostr note event");
  return Object.freeze({ id: validated.id, authorId: validated.pubkey, body: validated.content, createdAt: validated.created_at });
}

export function validatePublicEvent(event, { signed = false } = {}) {
  if (!event || typeof event !== "object" || Array.isArray(event)) throw new TypeError("public event must be an object");
  const allowed = new Set(["id", "pubkey", "created_at", "kind", "tags", "content", "sig"]);
  if (Object.keys(event).some((key) => !allowed.has(key))) throw new TypeError("public event contains unsupported or private fields");
  normalizePublicKey(event.pubkey);
  if (!Number.isInteger(event.created_at) || !Number.isInteger(event.kind) || typeof event.content !== "string" || !Array.isArray(event.tags)) throw new TypeError("malformed public event");
  if (!event.tags.every((tag) => Array.isArray(tag) && tag.every((value) => typeof value === "string"))) throw new TypeError("malformed event tags");
  if (event.id !== undefined && !/^[0-9a-fA-F]{64}$/.test(event.id)) throw new TypeError("malformed event id");
  if (event.sig !== undefined && !/^[0-9a-fA-F]{128}$/.test(event.sig)) throw new TypeError("malformed event signature");
  if (signed && (event.id === undefined || event.sig === undefined)) throw new TypeError("mapped relay event must be signed");
  return Object.freeze({ ...event, pubkey: normalizePublicKey(event.pubkey), tags: Object.freeze(event.tags.map((tag) => Object.freeze([...tag]))) });
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function copyArrayDataValues(value) {
  if (!Array.isArray(value)) throw new TypeError("relay filter list fields must be arrays");
  const copied = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) throw new TypeError("relay filter lists must contain explicit data values");
    copied.push(descriptor.value);
  }
  return copied;
}

function normalizeHexPrefixes(value) {
  const copied = copyArrayDataValues(value);
  if (!copied.every((item) => typeof item === "string" && HEX_PREFIX.test(item))) {
    throw new TypeError("relay filter identifier lists must contain only hexadecimal prefixes");
  }
  return Object.freeze(copied.map((item) => item.toLowerCase()));
}

function normalizeKinds(value) {
  const copied = copyArrayDataValues(value);
  if (!copied.every((kind) => Number.isSafeInteger(kind) && kind >= 0)) {
    throw new TypeError("relay filter kinds must be non-negative integers");
  }
  return Object.freeze(copied);
}

function normalizeNonNegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`relay filter ${field} must be a non-negative integer`);
  return value;
}

export function validatePublicRelayFilter(filter) {
  if (!isPlainObject(filter)) throw new TypeError("public relay filter must be a plain object");

  const keys = Reflect.ownKeys(filter);
  if (keys.some((key) => typeof key !== "string" || !PUBLIC_RELAY_FILTER_FIELD_SET.has(key))) {
    throw new TypeError("public relay filter contains unsupported fields");
  }

  const normalized = {};
  for (const field of PUBLIC_RELAY_FILTER_FIELDS) {
    if (!keys.includes(field)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(filter, field);
    if (!descriptor || !("value" in descriptor)) throw new TypeError("public relay filter fields must be data properties");
    const value = descriptor.value;

    if (field === "ids" || field === "authors" || field === "#e" || field === "#p") {
      normalized[field] = normalizeHexPrefixes(value);
    } else if (field === "kinds") {
      normalized[field] = normalizeKinds(value);
    } else if (field === "limit") {
      if (!Number.isSafeInteger(value) || value < 1 || value > MAX_RELAY_FILTER_LIMIT) {
        throw new TypeError(`relay filter limit must be an integer between 1 and ${MAX_RELAY_FILTER_LIMIT}`);
      }
      normalized[field] = value;
    } else {
      normalized[field] = normalizeNonNegativeInteger(value, field);
    }
  }

  return Object.freeze(normalized);
}

export function createNostrBoundary(adapter) {
  if (!adapter || typeof adapter.read !== "function" || typeof adapter.publish !== "function") throw new TypeError("relay adapter requires read and publish functions");
  return Object.freeze({
    read(filter) {
      const validated = validatePublicRelayFilter(filter);
      return adapter.read(validated);
    },
    publish(event) {
      const validated = validatePublicEvent(event);
      return adapter.publish(validated);
    }
  });
}
