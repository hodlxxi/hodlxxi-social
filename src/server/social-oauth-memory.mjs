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
export const createSessionStore = createBoundedStore;
