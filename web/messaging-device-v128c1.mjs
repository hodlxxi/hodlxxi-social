// Browser-local device lifecycle only. No message cryptography or transport.
const ROUTE = "/auth/messaging-device-bindings";
const PREFIX = "hodlxxi.social_messaging_device_binding_";
const LOCAL_SCHEMA = "hodlxxi.social_messaging_device_local.v1";
const HEX64 = /^[0-9a-f]{64}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const LOCAL_FIELDS = [
  "schema", "version", "subject", "deviceId", "privateKey", "publicKey",
  "requestId", "state", "acceptedBinding"
];
const METADATA_FIELDS = ["bindingId", "version", "validFrom", "expiresAt"];
const DEVICE_FIELDS = ["deviceId", "bindingId", "algorithm", "version", "publicKey", "validFrom", "expiresAt"];
const unavailable = () => { throw new Error("messaging device unavailable"); };
const hex = (value) => typeof value === "string" && HEX64.test(value);
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const bindingVersion = (value) => integer(value) && value >= 1 && value <= 1024;
const hexBytes = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== fields.length || keys.some((key) =>
    !fields.includes(key) || !descriptors[key].enumerable ||
    !Object.hasOwn(descriptors[key], "value")
  )) unavailable();
  return value;
}

function metadata(value) {
  exact(value, METADATA_FIELDS);
  if (!hex(value.bindingId) || !bindingVersion(value.version) ||
      !integer(value.validFrom) || !integer(value.expiresAt) ||
      value.expiresAt <= value.validFrom) unavailable();
  return value;
}

const acceptedMetadata = (device) => ({
  bindingId: device.bindingId,
  version: device.version,
  validFrom: device.validFrom,
  expiresAt: device.expiresAt
});
const sameMetadata = (a, b) => METADATA_FIELDS.every((field) => a[field] === b[field]);
const sameIdentity = (a, b) => ["subject", "deviceId", "publicKey", "requestId"].every((field) => a[field] === b[field]);

function privateCryptoKey(key, CryptoKeyImpl) {
  if (typeof CryptoKeyImpl !== "function" || !(key instanceof CryptoKeyImpl) ||
      key.type !== "private" || key.extractable !== false ||
      key.algorithm?.name !== "X25519" || key.usages.length !== 1 ||
      key.usages[0] !== "deriveBits") unavailable();
}

function localRecord(value, subject, CryptoKeyImpl) {
  exact(value, LOCAL_FIELDS);
  if (value.schema !== LOCAL_SCHEMA || value.version !== 1 ||
      !hex(value.subject) || value.subject !== subject ||
      !hex(value.deviceId) || !hex(value.publicKey) || !hex(value.requestId) ||
      !["pending-register", "ready", "unavailable"].includes(value.state)) unavailable();
  privateCryptoKey(value.privateKey, CryptoKeyImpl);
  if (value.acceptedBinding !== null) metadata(value.acceptedBinding);
  if (value.state === "ready" && value.acceptedBinding === null) unavailable();
  return value;
}

function snapshotDocument(value, now) {
  exact(value, ["schema", "version", "source", "snapshotId", "complete", "issuedAt", "expiresAt", "activeDevices"]);
  if (!integer(now) || value.schema !== PREFIX + "snapshot.v1" || value.version !== 1 ||
      value.source !== "hodlxxi-ubid" || typeof value.snapshotId !== "string" ||
      !SNAPSHOT_ID.test(value.snapshotId) || value.complete !== true ||
      !integer(value.issuedAt) || !integer(value.expiresAt) ||
      value.issuedAt > now || value.expiresAt <= now || value.expiresAt <= value.issuedAt ||
      !Array.isArray(value.activeDevices) || value.activeDevices.length > 16) unavailable();
  const ids = new Set(), keys = new Set(), bindings = new Set();
  for (const device of value.activeDevices) {
    exact(device, [...DEVICE_FIELDS, "snapshotId", "revoked"]);
    if (!hex(device.deviceId) || !hex(device.publicKey) || !hex(device.bindingId) ||
        device.algorithm !== "x25519-v1" || !bindingVersion(device.version) ||
        device.snapshotId !== value.snapshotId || device.revoked !== false ||
        !integer(device.validFrom) || !integer(device.expiresAt) ||
        device.validFrom > value.issuedAt || device.expiresAt <= now ||
        ids.has(device.deviceId) || keys.has(device.publicKey) || bindings.has(device.bindingId)) unavailable();
    ids.add(device.deviceId);
    keys.add(device.publicKey);
    bindings.add(device.bindingId);
  }
  return value;
}

function matchingBinding(snapshot, record) {
  const related = snapshot.activeDevices.filter((device) =>
    device.deviceId === record.deviceId || device.publicKey === record.publicKey);
  if (related.length === 0) return null;
  if (related.length !== 1 || related[0].deviceId !== record.deviceId ||
      related[0].publicKey !== record.publicKey ||
      (record.acceptedBinding && !sameMetadata(record.acceptedBinding, related[0]))) unavailable();
  return related[0];
}

function isoSeconds(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) unavailable();
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")) unavailable();
  return milliseconds / 1000;
}

function registerResult(value, record, now) {
  exact(value, ["schema", "version", "operation", "device"]);
  if (value.schema !== PREFIX + "result.v1" || value.version !== 1 || value.operation !== "register") unavailable();
  const device = exact(value.device, DEVICE_FIELDS);
  if (device.deviceId !== record.deviceId || device.publicKey !== record.publicKey ||
      device.algorithm !== "x25519-v1") unavailable();
  const accepted = metadata({
    bindingId: device.bindingId, version: device.version,
    validFrom: isoSeconds(device.validFrom), expiresAt: isoSeconds(device.expiresAt)
  });
  if (accepted.validFrom > now || accepted.expiresAt <= now ||
      (record.acceptedBinding && !sameMetadata(record.acceptedBinding, accepted))) unavailable();
  return accepted;
}

// A single slot cannot silently become a second account's device. add() is
// atomic across tabs; a concurrent first setup cannot overwrite the winner.
export function createMessagingDeviceStore(indexedDBImpl) {
  const open = () => new Promise((resolve, reject) => {
    // Access can itself throw in a browser with storage disabled. The Promise
    // turns that into a closed device failure rather than an auth-shell error.
    const factory = indexedDBImpl === undefined ? globalThis.indexedDB : indexedDBImpl;
    if (typeof factory?.open !== "function") { reject(new Error("device store unavailable")); return; }
    const request = factory.open("hodlxxi-social-messaging-device-v1", 1);
    let blocked = false;
    request.onupgradeneeded = () => request.result.createObjectStore("device");
    request.onerror = () => reject(new Error("device store unavailable"));
    request.onblocked = () => { blocked = true; reject(new Error("device store unavailable")); };
    request.onsuccess = () => {
      if (blocked) { request.result.close(); return; }
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
  const transaction = async (mode, action) => {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        let tx;
        try {
          tx = mode === "readwrite"
            ? db.transaction("device", mode, { durability: "strict" })
            : db.transaction("device", mode);
          // Fail closed if the platform ignores the required durability mode.
          if (mode === "readwrite" && tx.durability !== "strict") { tx.abort(); unavailable(); }
          let result;
          tx.oncomplete = () => resolve(result);
          tx.onabort = tx.onerror = () => reject(new Error("device store unavailable"));
          action(tx.objectStore("device"), (value) => { result = value; }, tx);
        } catch {
          try { tx?.abort(); } catch {}
          reject(new Error("device store unavailable"));
        }
      });
    } finally { db.close(); }
  };
  return Object.freeze({
    read: () => transaction("readonly", (store, done) => {
      const request = store.get("current");
      request.onsuccess = () => done(request.result);
    }),
    create: (record) => transaction("readwrite", (store) => {
      // Native IndexedDB structured clone; no private-key serialization.
      store.add(record, "current");
    }),
    update: (record) => transaction("readwrite", (store, done, tx) => {
      const request = store.get("current");
      request.onsuccess = () => {
        try {
          const previous = exact(request.result, LOCAL_FIELDS);
          if (!sameIdentity(previous, record) || previous.state === "unavailable" ||
              (previous.acceptedBinding && (!record.acceptedBinding ||
                !sameMetadata(previous.acceptedBinding, record.acceptedBinding)))) unavailable();
          // Preserve the stored key and never downgrade a concurrent ready write.
          store.put({ ...record, privateKey: previous.privateKey,
            state: previous.state === "ready" ? "ready" : record.state }, "current");
        } catch { tx.abort(); }
      };
    })
  });
}

export function createMessagingDevice({
  getContext,
  fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto,
  CryptoKeyImpl = globalThis.CryptoKey,
  randomFill = (bytes) => cryptoImpl.getRandomValues(bytes),
  store = createMessagingDeviceStore(),
  now = () => Math.floor(Date.now() / 1000),
  onState = () => {},
  setTimeoutImpl = globalThis.setTimeout,
  clearTimeoutImpl = globalThis.clearTimeout
} = {}) {
  let view = Object.freeze({ state: "unavailable", busy: false });
  let running = null;
  let generation = 0;
  let requestController = null;
  const publish = (state, busy = false) => {
    view = Object.freeze({ state, busy });
    onState(view); // Only a closed, key-free product projection leaves this module.
    return view;
  };
  const context = () => {
    const value = getContext?.();
    if (value?.access !== "full" || !hex(value.subject)) unavailable();
    return value.subject;
  };
  const request = async (url, command) => {
    const controller = new AbortController();
    requestController = controller;
    const timer = setTimeoutImpl(() => controller.abort(), 15000);
    try {
      const response = await fetchImpl(url, {
        method: command ? "POST" : "GET",
        credentials: "same-origin", cache: "no-store", redirect: "error",
        signal: controller.signal,
        headers: command
          ? { Accept: "application/json", "Content-Type": "application/json" }
          : { Accept: "application/json" },
        ...(command ? { body: JSON.stringify(command) } : {})
      });
      if (response?.status !== 200 || typeof response.text !== "function" ||
          !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(response.headers?.get?.("content-type") ?? "")) unavailable();
      const body = await response.text();
      if (typeof body !== "string" || !body.length ||
          new TextEncoder().encode(body).byteLength > (url === ROUTE ? 128 * 1024 : 1024)) unavailable();
      return JSON.parse(body);
    } finally {
      clearTimeoutImpl(timer);
      if (requestController === controller) requestController = null;
    }
  };
  const run = (create) => {
    if (running) return running;
    const epoch = generation;
    running = (async () => {
      let record;
      let subject;
      const check = () => { if (generation !== epoch || context() !== subject) unavailable(); };
      const session = async () => {
        check();
        const document = exact(await request("/auth/session"), ["authenticated", "subject"]);
        check();
        if (document.authenticated !== true || document.subject !== subject) unavailable();
      };
      const snapshot = async () => {
        await session();
        const value = snapshotDocument(await request(ROUTE), now());
        await session();
        return value;
      };
      const finalize = async (binding, serverSnapshot) => {
        await session();
        check();
        record = { ...record, state: "ready", acceptedBinding: acceptedMetadata(binding) };
        await store.update(record);
        await session();
        const retained = localRecord(await store.read(), subject, CryptoKeyImpl);
        if (!sameIdentity(retained, record) || retained.state !== "ready" ||
            !sameMetadata(retained.acceptedBinding, record.acceptedBinding)) unavailable();
        snapshotDocument(serverSnapshot, now());
        check();
        return publish("ready");
      };
      try {
        subject = context();
        publish(view.state, true);
        await session();
        if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.generateKey !== "function" ||
            typeof cryptoImpl.subtle.exportKey !== "function" || typeof randomFill !== "function") unavailable();
        record = await store.read();
        check();
        if (record !== undefined) {
          localRecord(record, subject, CryptoKeyImpl);
          if (record.state === "unavailable") unavailable();
          if (record.state === "pending-register") publish("pending-register", true);
        }
        const current = await snapshot();
        if (record === undefined) {
          if (!create) return publish("not-configured");
          await session();
          // WebCrypto X25519 Generate Key sets PUBLIC extractable=true and
          // applies false only to PRIVATE. Verify both before public export.
          const pair = await cryptoImpl.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
          check();
          privateCryptoKey(pair.privateKey, CryptoKeyImpl);
          if (!(pair.publicKey instanceof CryptoKeyImpl) || pair.publicKey.type !== "public" ||
              pair.publicKey.algorithm?.name !== "X25519" || pair.publicKey.extractable !== true ||
              pair.publicKey.usages.length !== 0) unavailable();
          const rawPublicKey = await cryptoImpl.subtle.exportKey("raw", pair.publicKey);
          if (!(rawPublicKey instanceof ArrayBuffer) || rawPublicKey.byteLength !== 32) unavailable();
          const randomId = () => {
            const bytes = new Uint8Array(32);
            if (randomFill(bytes) !== bytes) unavailable();
            return hexBytes(bytes);
          };
          record = {
            schema: LOCAL_SCHEMA, version: 1, subject,
            deviceId: randomId(), privateKey: pair.privateKey,
            publicKey: hexBytes(new Uint8Array(rawPublicKey)), requestId: randomId(),
            state: "pending-register", acceptedBinding: null
          };
          await session();
          // create() resolves ONLY from the strict IndexedDB tx.oncomplete.
          await store.create(record);
          check();
          const retained = localRecord(await store.read(), subject, CryptoKeyImpl);
          if (!sameIdentity(retained, record) || retained.state !== "pending-register") unavailable();
          record = retained;
          publish("pending-register", true);
        } else {
          const binding = matchingBinding(current, record);
          if (binding) return await finalize(binding, current);
          if (record.state === "ready" || record.acceptedBinding) unavailable();
        }
        await session();
        check();
        // Deliberate public allowlist: never stringify the local record.
        const command = {
          schema: PREFIX + "command.v1", version: 1, operation: "register",
          deviceId: record.deviceId, algorithm: "x25519-v1", publicKey: record.publicKey,
          expectedBindingId: null, requestId: record.requestId
        };
        let result;
        try { result = await request(ROUTE, command); }
        catch {
          await session();
          return publish("pending-register");
        }
        await session();
        let accepted;
        try { accepted = registerResult(result, record, now()); }
        catch { return publish("pending-register"); }
        record = { ...record, acceptedBinding: accepted };
        await store.update(record);
        const serverSnapshot = await snapshot();
        const binding = matchingBinding(serverSnapshot, record);
        if (!binding) unavailable();
        return await finalize(binding, serverSnapshot);
      } catch {
        // Preserve durable pending/ready material for inspection/re-entry.
        // Exceptions never enter the UI, telemetry, or logs.
        if (epoch === generation) return publish("unavailable");
        return view;
      }
    })().finally(() => { running = null; });
    return running;
  };
  return Object.freeze({
    reconcile: () => run(false),
    setup: () => run(true),
    view: () => view,
    cancel: () => { generation += 1; requestController?.abort(); publish("unavailable"); }
  });
}
