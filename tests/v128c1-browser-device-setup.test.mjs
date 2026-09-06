import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createMessagingDevice, createMessagingDeviceStore } from "../web/messaging-device-v128c1.mjs";
import { renderSecureMessagingAuthenticatedShell } from "../web/secure-messaging-v128.mjs";
import { normalizeMessagingDeviceSnapshot, normalizeMessagingDeviceResult } from "../src/server/ubid-messaging-device-client.mjs";

const subject = "a".repeat(64);
const secondSubject = "b".repeat(64);
const now = 1_788_652_800;
const route = "/auth/messaging-device-bindings";
const prefix = "hodlxxi.social_messaging_device_binding_";
const snapshotId = "sha256:" + "7".repeat(64);
const publicBytes = Uint8Array.from({ length: 32 }, (_, index) => 160 + index);
const publicHex = Buffer.from(publicBytes).toString("hex");
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
class TestCryptoKey {
  constructor(type, extractable = type === "public") {
    this.type = type;
    this.extractable = extractable;
    this.algorithm = { name: "X25519" };
    this.usages = type === "private" ? ["deriveBits"] : [];
  }
  toJSON() { throw new Error("CryptoKey must never be JSON serialized"); }
}
const pending = () => ({
  schema: "hodlxxi.social_messaging_device_local.v1", version: 1, subject,
  deviceId: "01".repeat(32), privateKey: new TestCryptoKey("private"),
  publicKey: publicHex, requestId: "02".repeat(32), state: "pending-register", acceptedBinding: null
});
const metadata = () => ({ bindingId: "3".repeat(64), version: 1, validFrom: now - 100, expiresAt: now + 86400 });
const active = (record = pending()) => ({
  deviceId: record.deviceId, publicKey: record.publicKey, algorithm: "x25519-v1",
  ...metadata(), snapshotId, revoked: false
});
const snapshot = (devices = []) => ({
  schema: prefix + "snapshot.v1", version: 1, source: "hodlxxi-ubid", snapshotId,
  complete: true, issuedAt: now - 10, expiresAt: now + 60, activeDevices: devices
});
const result = (record = pending()) => ({
  schema: prefix + "result.v1", version: 1, operation: "register",
  device: {
    deviceId: record.deviceId, publicKey: record.publicKey, algorithm: "x25519-v1", ...metadata(),
    validFrom: new Date((now - 100) * 1000).toISOString().replace(".000Z", "Z"),
    expiresAt: new Date((now + 86400) * 1000).toISOString().replace(".000Z", "Z")
  }
});
const response = (value) => ({
  status: 200, headers: { get: () => "application/json" },
  text: async () => JSON.stringify(value)
});
function harness(options = {}) {
  const events = [], calls = [], views = [], pairs = [], randomArrays = [];
  let stored = options.record;
  let registered = false;
  let currentSubject = subject;
  let access = "full";
  const store = {
    async read() { events.push("read-local"); return stored; },
    async create(record) {
      events.push("write-start");
      await options.commit?.(record);
      if (stored !== undefined) throw new Error("already exists");
      stored = record;
      events.push("write-committed");
    },
    async update(record) { await options.update?.(record); stored = record; events.push("update-committed"); }
  };
  const cryptoImpl = {
    subtle: {
      async generateKey(...args) {
        events.push("generate");
        assert.deepEqual(args, [{ name: "X25519" }, false, ["deriveBits"]]);
        await options.generate?.();
        const pair = options.pair ?? { publicKey: new TestCryptoKey("public"), privateKey: new TestCryptoKey("private") };
        pairs.push(pair);
        return pair;
      },
      async exportKey(format, key) {
        events.push("export-public");
        assert.equal(format, "raw");
        assert.equal(key, pairs.at(-1).publicKey);
        assert.notEqual(key, pairs.at(-1).privateKey);
        return options.raw ?? publicBytes.slice().buffer;
      }
    },
    getRandomValues(bytes) {
      assert.equal(bytes.byteLength, 32);
      randomArrays.push(bytes);
      events.push("random-32");
      bytes.fill(randomArrays.length);
      return bytes;
    }
  };
  const fetchImpl = async (url, init) => {
    calls.push([url, init]);
    events.push(`${init.method} ${url}`);
    if (url === "/auth/session") {
      await options.session?.();
      return response({ authenticated: true, subject: currentSubject });
    }
    assert.equal(url, route);
    if (init.method === "GET") {
      return response(options.snapshot ? await options.snapshot(stored, registered) : snapshot(registered ? [active(stored)] : []));
    }
    assert.equal(init.method, "POST");
    assert.ok(stored, "durably retained before network registration");
    await options.post?.(init, stored);
    registered = true;
    return options.postResponse ?? response(options.result ? options.result(stored) : result(stored));
  };
  const make = (overrides = {}) => createMessagingDevice({
    store, cryptoImpl, CryptoKeyImpl: TestCryptoKey, fetchImpl,
    getContext: () => ({ subject: currentSubject, access }), now: () => now,
    onState: (view) => views.push(view), ...overrides
  });
  return {
    make, controller: make(options.dependencies), events, calls, views, pairs, randomArrays, store,
    stored: () => stored, setSubject: (value) => { currentSubject = value; },
    setAccess: (value) => { access = value; },
    posts: () => calls.filter(([, init]) => init.method === "POST")
  };
}

test("native WebCrypto safely exports only the public X25519 key and structured-clones the non-extractable private key", async () => {
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  assert.equal(pair.privateKey.extractable, false);
  assert.equal(pair.publicKey.extractable, true);
  assert.equal((await webcrypto.subtle.exportKey("raw", pair.publicKey)).byteLength, 32);
  const clone = structuredClone(pair.privateKey);
  assert.equal(clone.type, "private");
  assert.equal(clone.algorithm.name, "X25519");
  assert.equal(clone.extractable, false);
  assert.deepEqual(clone.usages, ["deriveBits"]);
});

test("browser setup generates locally, exports only publicKey, and independently fills two secure 32-byte identifiers", async () => {
  const h = harness();
  assert.deepEqual(await h.controller.setup(), { state: "ready", busy: false });
  assert.equal(h.pairs.length, 1);
  assert.equal(h.stored().privateKey, h.pairs[0].privateKey);
  assert.equal(h.stored().privateKey.extractable, false);
  assert.equal(h.stored().publicKey, publicHex);
  assert.match(h.stored().publicKey, /^[0-9a-f]{64}$/);
  assert.equal(h.stored().deviceId, "01".repeat(32));
  assert.equal(h.stored().requestId, "02".repeat(32));
  assert.equal(h.randomArrays.length, 2);
  assert.notEqual(h.randomArrays[0], h.randomArrays[1]);
  assert.deepEqual(h.events.filter((event) => ["generate", "export-public", "random-32"].includes(event)),
    ["generate", "export-public", "random-32", "random-32"]);
});

for (const length of [0, 31, 33, 64]) test(`reject ${length}-byte public export without persistence or POST`, async () => {
  const h = harness({ raw: new ArrayBuffer(length) });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.stored(), undefined);
  assert.equal(h.posts().length, 0);
});

test("durable local pending commit completes before registration starts", async () => {
  const gate = deferred(), entered = deferred();
  const h = harness({ commit: async (record) => {
    assert.equal(record.state, "pending-register");
    assert.equal(record.privateKey.extractable, false);
    entered.resolve();
    await gate.promise;
  } });
  const work = h.controller.setup();
  await entered.promise;
  assert.equal(h.posts().length, 0);
  gate.resolve();
  assert.equal((await work).state, "ready");
  assert.ok(h.events.indexOf("write-committed") < h.events.indexOf(`POST ${route}`));
});

test("registration uses the exact public allowlist and same-origin BFF options", async () => {
  const h = harness();
  await h.controller.setup();
  const [url, init] = h.posts()[0];
  assert.equal(url, route);
  assert.deepEqual(JSON.parse(init.body), {
    schema: prefix + "command.v1", version: 1, operation: "register", deviceId: "01".repeat(32),
    algorithm: "x25519-v1", publicKey: publicHex, expectedBindingId: null, requestId: "02".repeat(32)
  });
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.cache, "no-store");
  assert.equal(init.redirect, "error");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.equal(Object.keys(init.headers).some((key) => key.toLowerCase() === "origin"), false);
  assert.doesNotMatch(init.body, /subject|private|alias|rc_|bitcoin|nostr|oauth|xpub|nsec|npub/i);
  assert.equal(init.body.includes(subject), false);
  for (const view of h.views) assert.deepEqual(Object.keys(view).sort(), ["busy", "state"]);
});

test("first startup is read-only and does not create a key", async () => {
  const h = harness();
  assert.equal((await h.controller.reconcile()).state, "not-configured");
  assert.equal(h.pairs.length, 0);
  assert.equal(h.posts().length, 0);
});

test("ambiguous POST retains pending and startup retry reuses every original field and the private key", async () => {
  let attempts = 0;
  const h = harness({ post: () => { if (++attempts === 1) throw new Error("connection lost"); } });
  assert.equal((await h.controller.setup()).state, "pending-register");
  const original = h.stored();
  const retry = h.make();
  const offset = h.calls.length;
  assert.equal((await retry.reconcile()).state, "ready");
  assert.equal(h.calls.slice(offset).find(([url]) => url === route)[1].method, "GET");
  assert.equal(h.pairs.length, 1);
  assert.equal(h.randomArrays.length, 2);
  for (const field of ["privateKey", "publicKey", "deviceId", "requestId"]) assert.equal(h.stored()[field], original[field]);
  assert.equal(h.posts()[0][1].body, h.posts()[1][1].body);
});

test("pending startup finalizes an exact active server binding without POST or key generation", async () => {
  const record = pending();
  const h = harness({ record, snapshot: () => snapshot([active(record)]) });
  assert.equal((await h.controller.reconcile()).state, "ready");
  assert.equal(h.posts().length, 0);
  assert.equal(h.pairs.length, 0);
  assert.deepEqual(h.stored().acceptedBinding, metadata());
});

test("ready requires matching accepted metadata and current server snapshot", async () => {
  const record = { ...pending(), state: "ready", acceptedBinding: metadata() };
  const h = harness({ record, snapshot: () => snapshot([active(record)]) });
  assert.equal((await h.controller.reconcile()).state, "ready");
  assert.equal(h.posts().length, 0);
});

test("another authenticated subject cannot adopt the local device", async () => {
  const h = harness({ record: pending() });
  h.setSubject(secondSubject);
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.posts().length, 0);
  assert.equal(h.pairs.length, 0);
  assert.equal(h.stored().subject, subject);
});

for (const [label, mutate] of [
  ["unknown schema", (r) => { r.schema = "unknown"; }],
  ["unknown version", (r) => { r.version = 2; }],
  ["missing CryptoKey", (r) => { delete r.privateKey; }],
  ["plain object key", (r) => { r.privateKey = {}; }],
  ["extractable private key", (r) => { r.privateKey.extractable = true; }],
  ["wrong key algorithm", (r) => { r.privateKey.algorithm.name = "Ed25519"; }],
  ["signing usage", (r) => { r.privateKey.usages = ["sign"]; }],
  ["unknown state", (r) => { r.state = "rotating"; }],
  ["extra secret field", (r) => { r.secret = "reject"; }],
  ["missing request id", (r) => { delete r.requestId; }],
  ["uppercase public key", (r) => { r.publicKey = publicHex.toUpperCase(); }],
  ["ready missing metadata", (r) => { r.state = "ready"; }],
  ["accessor field", (r) => { Object.defineProperty(r, "state", { enumerable: true, get() { throw new Error("must not invoke"); } }); }]
]) test(`malformed local record: ${label} fails closed without replacement`, async () => {
  const record = pending(); mutate(record);
  const h = harness({ record });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.posts().length, 0);
  assert.equal(h.pairs.length, 0);
});

for (const [label, mutate] of [
  ["unknown schema", (s) => { s.schema = "unknown"; }],
  ["extra subject", (s) => { s.subject = subject; }],
  ["incomplete", (s) => { s.complete = false; }],
  ["expired", (s) => { s.expiresAt = now; }],
  ["future", (s) => { s.issuedAt = now + 1; }],
  ["duplicate matching bindings", (s) => { s.activeDevices.push({ ...s.activeDevices[0] }); }],
  ["public key mismatch", (s) => { s.activeDevices[0].publicKey = "f".repeat(64); }],
  ["deviceId mismatch", (s) => { s.activeDevices[0].deviceId = "f".repeat(64); }],
  ["wrong algorithm", (s) => { s.activeDevices[0].algorithm = "unknown"; }],
  ["revoked", (s) => { s.activeDevices[0].revoked = true; }],
  ["wrong snapshot id", (s) => { s.activeDevices[0].snapshotId = "sha256:" + "9".repeat(64); }],
  ["binding not yet valid", (s) => { s.activeDevices[0].validFrom = now + 1; }],
  ["binding expires too early", (s) => { s.activeDevices[0].expiresAt = now; }]
]) test(`server reconciliation: ${label} cannot become ready or trigger replacement`, async () => {
  const record = pending(), server = snapshot([active(record)]); mutate(server);
  const h = harness({ record, snapshot: () => server });
  assert.equal((await h.controller.reconcile()).state, "unavailable");
  assert.equal(h.posts().length, 0);
  assert.equal(h.pairs.length, 0);
});

for (const field of ["bindingId", "version", "validFrom", "expiresAt"]) test(`ready rejects accepted ${field} mismatch`, async () => {
  const record = { ...pending(), state: "ready", acceptedBinding: metadata() };
  record.acceptedBinding[field] = field === "bindingId" ? "9".repeat(64) : record.acceptedBinding[field] + 1;
  const h = harness({ record, snapshot: () => snapshot([active(record)]) });
  assert.equal((await h.controller.reconcile()).state, "unavailable");
  assert.equal(h.posts().length, 0);
});

test("missing ready binding fails closed", async () => {
  const h = harness({ record: { ...pending(), state: "ready", acceptedBinding: metadata() } });
  assert.equal((await h.controller.reconcile()).state, "unavailable");
  assert.equal(h.posts().length, 0);
});

for (const [label, options] of [
  ["unsupported X25519", { generate: () => { throw new Error("NotSupportedError"); } }],
  ["missing WebCrypto", { dependencies: { cryptoImpl: null } }],
  ["IndexedDB unavailable", { dependencies: { store: createMessagingDeviceStore(null) } }],
  ["IndexedDB transaction failure", { commit: () => { throw new Error("QuotaExceededError"); } }],
  ["extractable key generation", { pair: { privateKey: new TestCryptoKey("private", true), publicKey: new TestCryptoKey("public") } }],
  ["non-exportable public key", { pair: { privateKey: new TestCryptoKey("private"), publicKey: new TestCryptoKey("public", false) } }]
]) test(`${label} prevents POST`, async () => {
  const h = harness(options);
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.posts().length, 0);
});

for (const [label, mutate] of [
  ["wrong schema", (r) => { r.schema = "unknown"; }],
  ["extra field", (r) => { r.subject = subject; }],
  ["rotate result", (r) => { r.operation = "rotate"; }],
  ["wrong key", (r) => { r.device.publicKey = "f".repeat(64); }],
  ["wrong device", (r) => { r.device.deviceId = "f".repeat(64); }],
  ["invalid binding", (r) => { r.device.bindingId = "invalid"; }],
  ["invalid date", (r) => { r.device.validFrom = "2026-02-31T00:00:00Z"; }],
  ["expired result", (r) => { r.device.expiresAt = "2000-01-01T00:00:00Z"; }]
]) test(`malformed register result (${label}) never becomes ready`, async () => {
  const h = harness({ result: (record) => { const value = result(record); mutate(value); return value; } });
  assert.equal((await h.controller.setup()).state, "pending-register");
  assert.equal(h.stored().state, "pending-register");
  assert.equal(h.stored().acceptedBinding, null);
  assert.equal(h.pairs.length, 1);
});

test("valid POST alone is insufficient: missing follow-up binding is unavailable", async () => {
  const h = harness({ snapshot: () => snapshot() });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.stored().state, "pending-register");
  assert.deepEqual(h.stored().acceptedBinding, metadata());
});

test("subject changes during generation prevent local commit and POST", async () => {
  const h = harness({ generate: () => h.setSubject(secondSubject) });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.stored(), undefined);
  assert.equal(h.posts().length, 0);
});

test("server session changes during local commit prevent POST and preserve original association", async () => {
  let changed = false;
  const h = harness({ commit: () => { changed = true; }, dependencies: {
    fetchImpl: async (url) => response(url === "/auth/session"
      ? { authenticated: true, subject: changed ? secondSubject : subject } : snapshot())
  } });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.stored().subject, subject);
  assert.equal(h.stored().state, "pending-register");
  assert.equal(h.posts().length, 0);
});

test("subject change during POST cannot finalize or reassign the key", async () => {
  const h = harness({ post: () => h.setSubject(secondSubject) });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.stored().subject, subject);
  assert.equal(h.stored().state, "pending-register");
});

test("Limited access does not read storage, generate keys, or initiate registration", async () => {
  const h = harness(); h.setAccess("limited");
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.deepEqual(h.events, []);
});

test("concurrent clicks share one setup and one key", async () => {
  const h = harness();
  const first = h.controller.setup(), second = h.controller.setup();
  assert.equal(first, second);
  await first;
  assert.equal(h.pairs.length, 1);
  assert.equal(h.posts().length, 1);
});

test("cancel during commit retains pending under its original subject without POST", async () => {
  const gate = deferred(), entered = deferred();
  const h = harness({ commit: async () => { entered.resolve(); await gate.promise; } });
  const work = h.controller.setup();
  await entered.promise; h.controller.cancel(); gate.resolve();
  assert.equal((await work).state, "unavailable");
  assert.equal(h.posts().length, 0);
  assert.equal(h.stored().subject, subject);
});

test("browser validators consume unchanged BFF snapshot/result field contracts", () => {
  assert.deepEqual(normalizeMessagingDeviceSnapshot(snapshot([active()])), snapshot([active()]));
  assert.deepEqual(normalizeMessagingDeviceResult(result()), result());
});

for (const [state, title] of [
  ["not-configured", "Set up secure messaging on this device"],
  ["pending-register", "Finishing secure device setup…"],
  ["ready", "This device is ready for end-to-end encryption"],
  ["unavailable", "Secure device state unavailable"]
]) test(`Messages renders ${state} without identity/key data and keeps composer disabled`, () => {
  const html = renderSecureMessagingAuthenticatedShell({ state: "available", recipients: [{ alias: "pairwise.member", label: "Brother" }] }, {
    deviceState: state, selectedAlias: "pairwise.member", privateKey: "never rendered", subject,
    deviceId: pending().deviceId, publicKey: publicHex, bindingId: metadata().bindingId
  });
  assert.ok(html.includes(title));
  assert.match(html, /textarea[^>]+disabled/);
  assert.match(html, /button type="submit" disabled/);
  assert.match(html, /Brother/);
  assert.equal(html.includes("data-secure-v128-setup-device"), state === "not-configured");
  for (const forbidden of [subject, pending().deviceId, publicHex, metadata().bindingId, "never rendered"]) assert.equal(html.includes(forbidden), false);
});

test("Limited Messages hides setup even if supplied a not-configured device state", () => {
  const html = renderSecureMessagingAuthenticatedShell({ state: "restricted", recipients: [] }, { deviceState: "not-configured" });
  assert.doesNotMatch(html, /data-secure-v128-setup-device/);
});

test("bounded module source permits only public export and same-origin session/device requests", async () => {
  const source = await readFile(new URL("../web/messaging-device-v128c1.mjs", import.meta.url), "utf8");
  for (const forbidden of [
    /localStorage/, /sessionStorage/, /window\.nostr/, /nip.?07/i, /\/internal\//,
    /https?:\/\//, /console\./, /\.derive(?:Key|Bits)\s*\(/, /\.(?:encrypt|decrypt|sign|wrapKey)\s*\(/,
    /(?:jwk|pkcs8)/i, /WebSocket/, /importKey\s*\(/
  ]) assert.doesNotMatch(source, forbidden);
  assert.deepEqual([...source.matchAll(/\.exportKey\(([^\n;]+)\)/g)].map((match) => match[1]), ['"raw", pair.publicKey']);
  assert.deepEqual([...source.matchAll(/JSON\.stringify\(([^)]+)\)/g)].map((match) => match[1]), ["command"]);
  assert.deepEqual([...source.matchAll(/"(\/auth\/[^" ]+)"/g)].map((match) => match[1]), [route, "/auth/session"]);
  assert.match(source, /store\.add\(record, "current"\)/);
  assert.match(source, /tx\.oncomplete = \(\) => resolve\(result\)/);
});

// Minimal event-driven IndexedDB seam. Native structuredClone models CryptoKey
// retention; write request success and transaction completion are independent.
function idbHarness({ holdWrites = false, abortWrites = false, durability = "strict" } = {}) {
  let value;
  const writes = [], events = [];
  const db = {
    close() { events.push("close"); },
    transaction(name, mode, options) {
      assert.equal(name, "device");
      if (mode === "readwrite") assert.deepEqual(options, { durability: "strict" });
      let aborted = false;
      const tx = {
        durability,
        abort() { aborted = true; queueMicrotask(() => tx.onabort?.()); },
        objectStore() {
          const operation = (action, write = false) => {
            const request = {};
            queueMicrotask(() => {
              if (aborted) return;
              try {
                const candidate = action();
                request.result = write ? undefined : candidate;
                request.onsuccess?.();
                if (write) {
                  events.push("request-success");
                  const finish = () => {
                    if (abortWrites) { tx.abort(); return; }
                    value = candidate;
                    events.push("transaction-complete");
                    tx.oncomplete?.();
                  };
                  if (holdWrites) writes.push(finish); else queueMicrotask(finish);
                } else if (mode === "readonly") queueMicrotask(() => tx.oncomplete?.());
              } catch { tx.abort(); }
            });
            return request;
          };
          return {
            get: () => operation(() => value === undefined ? undefined : structuredClone(value)),
            add: (record, key) => {
              assert.equal(key, "current");
              return operation(() => {
                if (value !== undefined) throw new Error("ConstraintError");
                return structuredClone(record);
              }, true);
            },
            put: (record, key) => {
              assert.equal(key, "current");
              return operation(() => structuredClone(record), true);
            }
          };
        }
      };
      return tx;
    }
  };
  return {
    factory: { open(name, version) {
      assert.equal(name, "hodlxxi-social-messaging-device-v1"); assert.equal(version, 1);
      const request = { result: db }; queueMicrotask(() => request.onsuccess()); return request;
    } },
    writes, events, stored: () => value
  };
}
const drain = async () => { for (let index = 0; index < 20; index++) await Promise.resolve(); };

test("native store waits for strict transaction completion, beyond successful add request", async () => {
  const idb = idbHarness({ holdWrites: true });
  const store = createMessagingDeviceStore(idb.factory);
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const record = { ...pending(), privateKey: pair.privateKey };
  let completed = false;
  const work = store.create(record).then(() => { completed = true; });
  await drain();
  assert.ok(idb.events.includes("request-success"));
  assert.equal(completed, false);
  assert.equal(idb.stored(), undefined);
  idb.writes.shift()(); await work;
  const retained = await store.read();
  assert.equal(retained.privateKey instanceof webcrypto.CryptoKey, true);
  assert.equal(retained.privateKey.extractable, false);
  assert.equal(retained.privateKey.type, "private");
  assert.equal(retained.publicKey, record.publicKey);
});

test("native store abort after successful add prevents registration", async () => {
  const idb = idbHarness({ abortWrites: true });
  const h = harness({ dependencies: { store: createMessagingDeviceStore(idb.factory),
    cryptoImpl: webcrypto, CryptoKeyImpl: webcrypto.CryptoKey } });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.ok(idb.events.includes("request-success"));
  assert.equal(idb.events.includes("transaction-complete"), false);
  assert.equal(h.posts().length, 0);
  assert.equal(idb.stored(), undefined);
});

test("native store fails closed when strict durability is unsupported", async () => {
  const idb = idbHarness({ durability: "default" });
  await assert.rejects(createMessagingDeviceStore(idb.factory).create(pending()), /device store unavailable/);
  assert.equal(idb.stored(), undefined);
});

test("native store cannot overwrite an existing account with add or update", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const record = { ...pending(), privateKey: pair.privateKey };
  await store.create(record);
  const other = { ...record, subject: secondSubject };
  await assert.rejects(store.create(other));
  await assert.rejects(store.update(other));
  assert.equal((await store.read()).subject, subject);
});

test("native store updates accepted metadata while retaining the cloned private key", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const record = { ...pending(), privateKey: pair.privateKey };
  await store.create(record);
  await store.update({ ...record, state: "ready", acceptedBinding: metadata(), privateKey: null });
  const ready = await store.read();
  assert.equal(ready.state, "ready");
  assert.equal(ready.privateKey.extractable, false);
  assert.deepEqual(ready.acceptedBinding, metadata());
  await assert.rejects(store.update({ ...record, acceptedBinding: { ...metadata(), bindingId: "8".repeat(64) } }));
});

test("neither localStorage nor sessionStorage is accessed during setup or reconciliation", async () => {
  const names = ["localStorage", "sessionStorage"];
  const descriptors = names.map((name) => Object.getOwnPropertyDescriptor(globalThis, name));
  let accesses = 0;
  try {
    for (const name of names) Object.defineProperty(globalThis, name, { configurable: true, get() { accesses++; throw new Error("forbidden storage"); } });
    const h = harness();
    assert.equal((await h.controller.setup()).state, "ready");
    assert.equal((await h.controller.reconcile()).state, "ready");
    assert.equal(accesses, 0);
  } finally {
    names.forEach((name, index) => {
      if (descriptors[index]) Object.defineProperty(globalThis, name, descriptors[index]);
      else delete globalThis[name];
    });
  }
});

test("timed-out POST stays pending and exact retry remains possible", async () => {
  let expire;
  const h = harness({ dependencies: {
    setTimeoutImpl: (callback) => { expire = callback; return 1; }, clearTimeoutImpl: () => {}
  }, post: (init) => new Promise((resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(new Error("timeout")));
    expire();
  }) });
  assert.equal((await h.controller.setup()).state, "pending-register");
  assert.equal(h.stored().state, "pending-register");
  assert.equal(h.pairs.length, 1);
});

test("a browser that throws on IndexedDB access reports unavailable without POST", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  try {
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, get() { throw new Error("storage disabled"); } });
    const h = harness({ dependencies: { store: createMessagingDeviceStore() } });
    assert.equal((await h.controller.setup()).state, "unavailable");
    assert.equal(h.posts().length, 0);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "indexedDB", descriptor);
    else delete globalThis.indexedDB;
  }
});

test("invalid injected time fails closed rather than accepting freshness comparisons", async () => {
  const h = harness({ dependencies: { now: () => NaN } });
  assert.equal((await h.controller.setup()).state, "unavailable");
  assert.equal(h.posts().length, 0);
});
