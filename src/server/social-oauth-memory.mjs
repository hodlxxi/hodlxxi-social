import { types } from "node:util";
const check = (value, name) => { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`invalid ${name}`); };
export function createBoundedStore({ ttlSeconds, capacity, now = Date.now }) {
  check(ttlSeconds, "ttl"); check(capacity, "capacity");
  if (typeof now !== "function") throw new TypeError("invalid clock");
  const entries = new Map();
  const sweep = () => { const time = now(); for (const [key, record] of entries) if (record.expiresAt <= time) entries.delete(key); };
  const create = (key, value) => {
    sweep();
    if (typeof key !== "string" || !key || entries.has(key)) return false;
    if (entries.size >= capacity) return false;
    const issuedAt = now(); entries.set(key, Object.freeze({ ...value, issuedAt, expiresAt: issuedAt + ttlSeconds * 1000 })); return true;
  };
  const get = (key) => { sweep(); return entries.get(key) ?? null; };
  const consume = (key) => { const value = get(key); if (value !== null) entries.delete(key); return value; };
  const consumeIf = (key, predicate) => {
    if (typeof predicate !== "function") throw new TypeError("invalid predicate");
    const value = get(key);
    if (value === null || predicate(value) !== true) return null;
    entries.delete(key);
    return value;
  };
  const remove = (key) => entries.delete(key);
  return Object.freeze({ create, get, consume, consumeIf, delete: remove, get size() { sweep(); return entries.size; } });
}
export const createPendingTransactionStore = createBoundedStore;
// Mobile entries are presentations of UBID authority, with absolute deadlines.
// Retain an expired original credential for at most five minutes solely so an
// explicit logout can cancel it. get() never exposes that retention as authority.
export function createSessionStore({ ttlSeconds, capacity, now = Date.now }) {
  check(ttlSeconds, "ttl"); check(capacity, "capacity");
  if (typeof now !== "function") throw new TypeError("invalid clock");
  const entries = new Map();
  const mobile = (v) => Object.hasOwn(v, "kind") || Object.hasOwn(v, "issuanceId");
  const sweep = () => {
    const time = now();
    for (const [key, entry] of entries) {
      const deadline = entry.logout?.until ??
        entry.record.expiresAt + (entry.record.kind === "ubid-mobile-v1" ? 300000 : 0);
      if (deadline <= time) entries.delete(key);
    }
  };
  const create = (key, value) => {
    sweep();
    if (typeof key !== "string" || !key || entries.has(key) || entries.size >= capacity) return false;
    if (types.isProxy(value) || !value || typeof value !== "object") throw new TypeError("invalid session");
    let record;
    if (mobile(value)) {
      const d = Object.getOwnPropertyDescriptors(value);
      const fields = ["kind", "subject", "viewerAccessToken", "issuanceId", "issuedAt", "expiresAt"];
      if (Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(d).length !== fields.length ||
          fields.some((f) => !d[f]?.enumerable || !Object.hasOwn(d[f], "value")) ||
          value.kind !== "ubid-mobile-v1" || typeof value.subject !== "string" || typeof value.issuanceId !== "string" ||
          !/^[0-9a-f]{64}$/.test(value.subject) || !/^[0-9a-f]{64}$/.test(value.issuanceId) ||
          typeof value.viewerAccessToken !== "string" || value.viewerAccessToken.length > 8192 ||
          !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.viewerAccessToken) ||
          !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
          value.issuedAt % 1000 || value.expiresAt % 1000 || value.issuedAt > now() ||
          value.expiresAt - value.issuedAt > 300000 || value.expiresAt - now() < 1000) throw new TypeError("invalid mobile session");
      record = { ...value };
    } else record = { ...value, issuedAt: now(), expiresAt: now() + ttlSeconds * 1000 };
    // The bounded slot also owns any future local-denial/retry state. Logout
    // must not depend on allocating space in a second, possibly full queue.
    entries.set(key, { record: Object.freeze(record), logout: null }); return true;
  };
  const getForLogout = (key) => { sweep(); return entries.get(key)?.record ?? null; };
  const getLogoutState = (key) => { sweep(); return entries.get(key)?.logout ?? null; };
  const beginLogout = (key) => {
    sweep();
    const entry = entries.get(key);
    if (!entry) return null;
    // Fixed, non-renewable cancellation-only retention; never authentication.
    if (!entry.logout) entry.logout = { original: entry.record, until: now() + 300000, confirmed: false };
    return entry.logout;
  };
  const get = (key) => {
    sweep();
    const entry = entries.get(key);
    return entry && !entry.logout && entry.record.expiresAt > now() ? entry.record : null;
  };
  const consume = (key) => { const v = get(key); if (v) entries.delete(key); return v; };
  const consumeIf = (key, predicate) => { const v = get(key); if (!v || predicate(v) !== true) return null; entries.delete(key); return v; };
  return Object.freeze({ create, get, getForLogout, getLogoutState, beginLogout, consume, consumeIf, delete: (key) => entries.delete(key), get size() { sweep(); return entries.size; } });
}
