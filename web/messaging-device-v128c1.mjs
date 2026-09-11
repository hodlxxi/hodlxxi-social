import {
  authorizeMessagingDeviceBinding,
  canonicalMessagingDeviceAuthorizationProposal,
  canonicalMessagingDeviceJson,
  parseMessagingDeviceAuthorizationRetry
} from "./messaging-device-authorization-v1.mjs?v=1.28.1";

// Browser-local device lifecycle only. No message cryptography or transport.
const ROUTE = "/auth/messaging-device-bindings";
const PREFIX = "hodlxxi.social_messaging_device_binding_";
const LOCAL_SCHEMA = "hodlxxi.social_messaging_device_local.v1";
const HEX64 = /^[0-9a-f]{64}$/;
const PROOF_ID = /^hodlxxi-binding-authorization-v1-sha256:[0-9a-f]{64}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const LEGACY_LOCAL_FIELDS = [
  "schema", "version", "subject", "deviceId", "privateKey", "publicKey",
  "requestId", "state", "acceptedBinding"
];
const AUTHORIZATION_LOCAL_FIELDS = [
  ...LEGACY_LOCAL_FIELDS, "authorization", "pendingAuthorization", "rotation"
];
const LOCAL_FIELDS = [...AUTHORIZATION_LOCAL_FIELDS, "pendingProposal"];
const METADATA_FIELDS = ["bindingId", "version", "validFrom", "expiresAt"];
const AUTHORIZATION_FIELDS = ["action", "bindingId", "proofId", "requestId"];
const ROTATION_FIELDS = ["privateKey", "publicKey", "requestId"];
const DEVICE_FIELDS = ["deviceId", "bindingId", "algorithm", "version", "publicKey", "validFrom", "expiresAt"];
const AUTHORIZATION_STATES = [
  "pending-register", "authorization-required", "pending-adopt", "ready",
  "pending-rotate", "pending-revoke", "revoked", "unavailable"
];
export const MESSAGING_DEVICE_TIMESTAMP_UNIT = "unix-milliseconds";
const unavailable = () => { throw new Error("messaging device unavailable"); };
const hex = (value) => typeof value === "string" && HEX64.test(value);
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const validBindingVersion = (value) => integer(value) && value >= 1 && value <= 1024;
const hexBytes = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== fields.length || keys.some((key) =>
    typeof key !== "string" || !fields.includes(key) || !descriptors[key].enumerable ||
    !Object.hasOwn(descriptors[key], "value")
  ) || fields.some((field) => !Object.hasOwn(descriptors, field))) unavailable();
  return value;
}

function metadata(value) {
  exact(value, METADATA_FIELDS);
  if (!hex(value.bindingId) || !validBindingVersion(value.version) ||
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
const sameBaseIdentity = (a, b) =>
  a.subject === b.subject && a.deviceId === b.deviceId;
const sameActiveIdentity = (a, b) =>
  sameBaseIdentity(a, b) && a.publicKey === b.publicKey && a.requestId === b.requestId;

function privateCryptoKey(key, CryptoKeyImpl) {
  if (typeof CryptoKeyImpl !== "function" || !(key instanceof CryptoKeyImpl) ||
      key.type !== "private" || key.extractable !== false ||
      key.algorithm?.name !== "X25519" || key.usages.length !== 1 ||
      key.usages[0] !== "deriveBits") unavailable();
}

function authorizationMarker(value) {
  exact(value, AUTHORIZATION_FIELDS);
  if (!["register", "adopt", "rotate", "revoke"].includes(value.action) ||
      !hex(value.bindingId) || !PROOF_ID.test(value.proofId) ||
      !hex(value.requestId)) unavailable();
  return value;
}

function localFields(value) {
  const keys = value && Object.getPrototypeOf(value) === Object.prototype
    ? Reflect.ownKeys(Object.getOwnPropertyDescriptors(value))
    : [];
  for (const fields of [LEGACY_LOCAL_FIELDS, AUTHORIZATION_LOCAL_FIELDS, LOCAL_FIELDS]) {
    if (keys.length === fields.length &&
        keys.every((key) => typeof key === "string" && fields.includes(key))) return fields;
  }
  unavailable();
}

function inferredPendingProposal(record) {
  if (Object.hasOwn(record, "pendingProposal")) return record.pendingProposal;
  if (typeof record.pendingAuthorization?.proposal === "string") {
    return record.pendingAuthorization.proposal;
  }
  try {
    if (record.state === "pending-register") return canonicalMessagingDeviceAuthorizationProposal({
      deviceId: record.deviceId,
      expectedBindingId: null,
      operation: "register",
      publicKey: record.publicKey,
      requestId: record.requestId
    });
    if (record.state === "pending-rotate" && record.rotation && record.acceptedBinding) {
      return canonicalMessagingDeviceAuthorizationProposal({
        deviceId: record.deviceId,
        expectedBindingId: record.acceptedBinding.bindingId,
        operation: "rotate",
        publicKey: record.rotation.publicKey,
        requestId: record.rotation.requestId
      });
    }
  } catch { unavailable(); }
  return null;
}

function localRecord(value, subject, CryptoKeyImpl) {
  const fields = localFields(value);
  exact(value, fields);
  const record = fields === LEGACY_LOCAL_FIELDS ? {
    ...value,
    authorization: null,
    pendingAuthorization: null,
    rotation: null,
    pendingProposal: inferredPendingProposal(value)
  } : fields === AUTHORIZATION_LOCAL_FIELDS ? {
    ...value,
    pendingProposal: inferredPendingProposal(value)
  } : value;
  if (record.schema !== LOCAL_SCHEMA || record.version !== 1 ||
      !hex(record.subject) || record.subject !== subject ||
      !hex(record.deviceId) || !hex(record.publicKey) || !hex(record.requestId) ||
      !AUTHORIZATION_STATES.includes(record.state)) unavailable();
  privateCryptoKey(record.privateKey, CryptoKeyImpl);
  if (record.acceptedBinding !== null) metadata(record.acceptedBinding);
  if (record.authorization !== null) authorizationMarker(record.authorization);
  if (record.pendingAuthorization !== null &&
      (!record.pendingAuthorization ||
       Object.getPrototypeOf(record.pendingAuthorization) !== Object.prototype)) unavailable();
  if (record.pendingProposal !== null && typeof record.pendingProposal !== "string") unavailable();
  if (record.rotation !== null) {
    exact(record.rotation, ROTATION_FIELDS);
    privateCryptoKey(record.rotation.privateKey, CryptoKeyImpl);
    if (!hex(record.rotation.publicKey) || !hex(record.rotation.requestId) ||
        record.rotation.publicKey === record.publicKey) unavailable();
  }
  if (record.state === "ready" && record.acceptedBinding === null) unavailable();
  if (record.state === "pending-rotate" && record.rotation === null) unavailable();
  if (record.rotation !== null && record.state !== "pending-rotate") unavailable();
  if (["pending-adopt", "pending-revoke"].includes(record.state) &&
      record.acceptedBinding === null) unavailable();
  if (record.pendingProposal !== null) {
    let proposal;
    try {
      proposal = JSON.parse(record.pendingProposal);
      if (canonicalMessagingDeviceAuthorizationProposal(proposal) !== record.pendingProposal) unavailable();
    } catch { unavailable(); }
    const expectedState = proposal.operation === "adopt"
      ? "pending-adopt" : `pending-${proposal.operation}`;
    if (record.state !== expectedState ||
        (proposal.operation === "register" &&
          (proposal.deviceId !== record.deviceId || proposal.publicKey !== record.publicKey ||
           proposal.requestId !== record.requestId)) ||
        (proposal.operation === "rotate" &&
          (!record.rotation || proposal.deviceId !== record.deviceId ||
           proposal.publicKey !== record.rotation.publicKey ||
           proposal.requestId !== record.rotation.requestId ||
           proposal.expectedBindingId !== record.acceptedBinding?.bindingId)) ||
        (proposal.operation === "adopt" &&
          (proposal.bindingId !== record.acceptedBinding?.bindingId ||
           proposal.requestId === record.requestId)) ||
        (proposal.operation === "revoke" &&
          (proposal.deviceId !== record.deviceId || proposal.publicKey !== null ||
           proposal.expectedBindingId !== record.acceptedBinding?.bindingId ||
           proposal.requestId === record.requestId))) unavailable();
  }
  if (record.pendingAuthorization !== null &&
      record.pendingAuthorization.proposal !== record.pendingProposal) unavailable();
  if (!["pending-register", "pending-adopt", "pending-rotate", "pending-revoke"].includes(record.state) &&
      (record.pendingProposal !== null || record.pendingAuthorization !== null)) unavailable();
  return record;
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
        device.algorithm !== "x25519-v1" || !validBindingVersion(device.version) ||
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

function relatedBindings(snapshot, deviceId, publicKey) {
  return snapshot.activeDevices.filter((device) =>
    device.deviceId === deviceId || device.publicKey === publicKey);
}

function exactBinding(snapshot, { deviceId, publicKey, bindingId, acceptedBinding = null }) {
  const related = relatedBindings(snapshot, deviceId, publicKey);
  if (related.length === 0) return null;
  if (related.length !== 1 || related[0].deviceId !== deviceId ||
      related[0].publicKey !== publicKey ||
      (bindingId !== undefined && related[0].bindingId !== bindingId) ||
      (acceptedBinding && !sameMetadata(acceptedBinding, related[0]))) unavailable();
  return related[0];
}

function acceptedRotationBinding(snapshot, record, bindingId) {
  const related = snapshot.activeDevices.filter((device) =>
    device.deviceId === record.deviceId || device.publicKey === record.rotation.publicKey ||
    device.bindingId === bindingId);
  if (related.length !== 1) unavailable();
  const device = related[0];
  if (device.deviceId === record.deviceId &&
      device.publicKey === record.rotation.publicKey && device.bindingId === bindingId) {
    return device;
  }
  if (device.deviceId === record.deviceId && device.publicKey === record.publicKey &&
      record.acceptedBinding && sameMetadata(device, record.acceptedBinding)) return null;
  unavailable();
}

function isoMilliseconds(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) unavailable();
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) ||
      new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")) unavailable();
  return milliseconds;
}

function legacyRegisterResult(value, record, now) {
  exact(value, ["schema", "version", "operation", "device"]);
  if (value.schema !== PREFIX + "result.v1" || value.version !== 1 ||
      value.operation !== "register") unavailable();
  const device = exact(value.device, DEVICE_FIELDS);
  if (device.deviceId !== record.deviceId || device.publicKey !== record.publicKey ||
      device.algorithm !== "x25519-v1") unavailable();
  const accepted = metadata({
    bindingId: device.bindingId,
    version: device.version,
    validFrom: isoMilliseconds(device.validFrom),
    expiresAt: isoMilliseconds(device.expiresAt)
  });
  if (accepted.validFrom > now || accepted.expiresAt <= now ||
      (record.acceptedBinding && !sameMetadata(record.acceptedBinding, accepted))) unavailable();
  return accepted;
}

function authorizedResult(value, proposal, currentBinding, now) {
  exact(value, [
    "action", "active", "authorizationExpiresAt", "authorizationProofId",
    "authorizationValidFrom", "bindingId", "bindingOperation", "bindingVersion",
    "deviceId", "expiresAt", "requestId", "schema", "validFrom", "version"
  ]);
  const operation = proposal.operation;
  const expectedDeviceId = operation === "adopt" ? currentBinding?.deviceId : proposal.deviceId;
  const expectedVersion = operation === "register" ? 1
    : operation === "adopt" ? currentBinding?.version
      : currentBinding?.version + 1;
  const expectedBindingOperation = operation === "adopt"
    ? (currentBinding?.version === 1 ? "register" : "rotate")
    : operation;
  if (
    value.schema !== PREFIX + "authorization_result.v1" || value.version !== 1 ||
    value.action !== operation || value.active !== (operation !== "revoke") ||
    value.bindingOperation !== expectedBindingOperation ||
    value.bindingVersion !== expectedVersion || value.deviceId !== expectedDeviceId ||
    value.requestId !== proposal.requestId || !hex(value.bindingId) ||
    !PROOF_ID.test(value.authorizationProofId) ||
    (operation === "adopt" && value.bindingId !== proposal.bindingId)
  ) unavailable();
  const accepted = metadata({
    bindingId: value.bindingId,
    version: value.bindingVersion,
    validFrom: isoMilliseconds(value.validFrom),
    expiresAt: isoMilliseconds(value.expiresAt)
  });
  if (isoMilliseconds(value.authorizationValidFrom) > now ||
      isoMilliseconds(value.authorizationExpiresAt) !== accepted.expiresAt ||
      accepted.validFrom > now || accepted.expiresAt <= now) unavailable();
  return Object.freeze({
    accepted,
    marker: Object.freeze({
      action: operation,
      bindingId: value.bindingId,
      proofId: value.authorizationProofId,
      requestId: value.requestId
    })
  });
}

const extended = (record) => ({
  ...record,
  authorization: record.authorization ?? null,
  pendingAuthorization: record.pendingAuthorization ?? null,
  rotation: record.rotation ?? null,
  pendingProposal: inferredPendingProposal(record)
});

const samePublicRecordRevision = (a, b) => {
  try {
    const publicRevision = (record) => canonicalMessagingDeviceJson({
      acceptedBinding: record.acceptedBinding,
      authorization: record.authorization,
      deviceId: record.deviceId,
      pendingAuthorization: record.pendingAuthorization,
      pendingProposal: record.pendingProposal,
      publicKey: record.publicKey,
      requestId: record.requestId,
      rotation: record.rotation === null ? null : {
        publicKey: record.rotation.publicKey,
        requestId: record.rotation.requestId
      },
      schema: record.schema,
      state: record.state,
      subject: record.subject,
      version: record.version
    });
    return publicRevision(a) === publicRevision(b);
  } catch { return false; }
};

// A single slot cannot silently become a second account's device. add() is
// atomic across tabs; native IndexedDB structured clone retains CryptoKeys.
export function createMessagingDeviceStore(indexedDBImpl) {
  const open = () => new Promise((resolve, reject) => {
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
    read: () => transaction("readonly", (deviceStore, done) => {
      const request = deviceStore.get("current");
      request.onsuccess = () => done(request.result);
    }),
    create: (record) => transaction("readwrite", (store) => {
      const next = extended(record);
      const CryptoKeyImpl = next.privateKey?.constructor;
      store.add(localRecord(next, next.subject, CryptoKeyImpl), "current");
    }),
    update: (record, expectedRecord) => transaction("readwrite", (deviceStore, _done, tx) => {
      const request = deviceStore.get("current");
      request.onsuccess = () => {
        try {
          const previousRaw = request.result;
          const CryptoKeyImpl = previousRaw?.privateKey?.constructor;
          const previous = localRecord(previousRaw, previousRaw?.subject, CryptoKeyImpl);
          const expected = localRecord(expectedRecord, previous.subject, CryptoKeyImpl);
          let next = extended(record);
          if (!samePublicRecordRevision(previous, expected)) unavailable();
          if (!sameBaseIdentity(previous, next)) unavailable();
          const promotesRotation = previous.rotation !== null && next.rotation === null &&
            next.publicKey === previous.rotation.publicKey &&
            next.requestId === previous.rotation.requestId && next.state === "ready" &&
            next.authorization?.action === "rotate" &&
            next.authorization.requestId === previous.rotation.requestId;
          if (!promotesRotation && !sameActiveIdentity(previous, next)) unavailable();
          if (previous.acceptedBinding && !next.acceptedBinding) unavailable();
          if (previous.acceptedBinding && next.acceptedBinding &&
              !sameMetadata(previous.acceptedBinding, next.acceptedBinding) &&
              !promotesRotation) unavailable();
          if (previous.authorization && next.authorization === null) unavailable();
          if (previous.rotation && next.rotation === null && !promotesRotation) unavailable();
          if (previous.rotation && next.rotation &&
              (previous.rotation.publicKey !== next.rotation.publicKey ||
               previous.rotation.requestId !== next.rotation.requestId)) unavailable();
          if (previous.pendingProposal !== null && next.pendingProposal !== null &&
              previous.pendingProposal !== next.pendingProposal) unavailable();
          if (previous.pendingAuthorization !== null && next.pendingAuthorization !== null &&
              canonicalMessagingDeviceJson(previous.pendingAuthorization) !==
                canonicalMessagingDeviceJson(next.pendingAuthorization) &&
              previous.pendingProposal !== next.pendingProposal) unavailable();
          if (previous.pendingAuthorization !== null && next.pendingAuthorization === null &&
              !["ready", "revoked"].includes(next.state)) unavailable();
          if (previous.pendingProposal !== null && next.pendingProposal === null &&
              !["ready", "revoked"].includes(next.state)) unavailable();
          const privateKey = promotesRotation
            ? previous.rotation.privateKey : previous.privateKey;
          const rotation = next.rotation && previous.rotation
            ? { ...next.rotation, privateKey: previous.rotation.privateKey }
            : next.rotation;
          next = { ...next, privateKey, rotation };
          localRecord(next, previous.subject, CryptoKeyImpl);
          deviceStore.put(next, "current");
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
  now = Date.now,
  onState = () => {},
  setTimeoutImpl = globalThis.setTimeout,
  clearTimeoutImpl = globalThis.clearTimeout,
  authorizationEnabled = false,
  authorizationSigner,
  authorizeBinding = authorizeMessagingDeviceBinding,
  parseAuthorizationRetry = parseMessagingDeviceAuthorizationRetry
} = {}) {
  let view = Object.freeze({ state: "unavailable", busy: false });
  let running = null;
  let generation = 0;
  let requestController = null;
  const publish = (state, busy = false) => {
    view = Object.freeze({ state, busy });
    onState(view);
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
  const run = (explicitAction) => {
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
      const readSnapshot = async () => {
        await session();
        const value = snapshotDocument(await request(ROUTE), now());
        await session();
        return value;
      };
      const readBack = async () => {
        check();
        return localRecord(await store.read(), subject, CryptoKeyImpl);
      };
      const write = async (next) => {
        check();
        const expected = record;
        await store.update(extended(next), extended(expected));
        record = await readBack();
        return record;
      };
      const randomId = (differentFrom) => {
        for (let attempt = 0; attempt < 4; attempt += 1) {
          const bytes = new Uint8Array(32);
          if (randomFill(bytes) !== bytes) unavailable();
          const id = hexBytes(bytes);
          if (id !== differentFrom) return id;
        }
        unavailable();
      };
      const generateKeyMaterial = async () => {
        if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.generateKey !== "function" ||
            typeof cryptoImpl.subtle.exportKey !== "function" || typeof randomFill !== "function") unavailable();
        const pair = await cryptoImpl.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
        check();
        privateCryptoKey(pair.privateKey, CryptoKeyImpl);
        if (!(pair.publicKey instanceof CryptoKeyImpl) || pair.publicKey.type !== "public" ||
            pair.publicKey.algorithm?.name !== "X25519" || pair.publicKey.extractable !== true ||
            pair.publicKey.usages.length !== 0) unavailable();
        const rawPublicKey = await cryptoImpl.subtle.exportKey("raw", pair.publicKey);
        if (!(rawPublicKey instanceof ArrayBuffer) || rawPublicKey.byteLength !== 32) unavailable();
        return Object.freeze({
          privateKey: pair.privateKey,
          publicKey: hexBytes(new Uint8Array(rawPublicKey))
        });
      };
      const markerFromRetry = (checked) => Object.freeze({
        action: checked.action,
        bindingId: checked.bindingId,
        proofId: checked.proofId,
        requestId: checked.requestId
      });
      const finalizeReady = async (binding, marker, { promoteRotation = false } = {}) => {
        await session();
        check();
        const next = {
          ...record,
          ...(promoteRotation ? {
            privateKey: record.rotation.privateKey,
            publicKey: record.rotation.publicKey,
            requestId: record.rotation.requestId
          } : {}),
          acceptedBinding: acceptedMetadata(binding),
          authorization: marker,
          pendingAuthorization: null,
          pendingProposal: null,
          rotation: null,
          state: "ready"
        };
        await write(next);
        if (record.state !== "ready" || !sameMetadata(record.acceptedBinding, binding) ||
            record.authorization.bindingId !== binding.bindingId) unavailable();
        await session();
        return publish("ready");
      };
      const finalizeRevoked = async (marker) => {
        await session();
        await write({
          ...record,
          authorization: marker,
          pendingAuthorization: null,
          pendingProposal: null,
          rotation: null,
          state: "revoked"
        });
        await session();
        return publish("revoked");
      };
      const proposalForPending = () => {
        const stored = record.pendingProposal;
        if (typeof stored !== "string") unavailable();
        let proposal;
        try { proposal = JSON.parse(stored); } catch { unavailable(); }
        if (canonicalMessagingDeviceAuthorizationProposal(proposal) !== stored) unavailable();
        if (proposal.operation === "register") {
          if (record.state !== "pending-register" || proposal.deviceId !== record.deviceId ||
              proposal.publicKey !== record.publicKey || proposal.requestId !== record.requestId) unavailable();
        } else if (proposal.operation === "rotate") {
          if (record.state !== "pending-rotate" || !record.rotation ||
              proposal.deviceId !== record.deviceId ||
              proposal.publicKey !== record.rotation.publicKey ||
              proposal.requestId !== record.rotation.requestId ||
              proposal.expectedBindingId !== record.acceptedBinding?.bindingId) unavailable();
        } else if (proposal.operation === "adopt") {
          if (record.state !== "pending-adopt" ||
              proposal.bindingId !== record.acceptedBinding?.bindingId ||
              proposal.requestId === record.requestId) unavailable();
        } else if (proposal.operation !== "revoke" || record.state !== "pending-revoke" ||
          proposal.deviceId !== record.deviceId ||
          proposal.expectedBindingId !== record.acceptedBinding?.bindingId) unavailable();
        return proposal;
      };
      const pendingState = (operation) => operation === "adopt"
        ? "pending-adopt" : `pending-${operation}`;
      const reconcileRetainedAuthorization = async (snapshot, proposal, checked) => {
        const marker = markerFromRetry(checked);
        if (proposal.operation === "register") {
          const binding = exactBinding(snapshot, {
            deviceId: record.deviceId, publicKey: record.publicKey,
            bindingId: checked.bindingId
          });
          if (binding) return finalizeReady(binding, marker);
        } else if (proposal.operation === "rotate") {
          const binding = acceptedRotationBinding(snapshot, record, checked.bindingId);
          if (binding) return finalizeReady(binding, marker, { promoteRotation: true });
        } else if (proposal.operation === "revoke" &&
          relatedBindings(snapshot, record.deviceId, record.publicKey).length === 0) {
          return finalizeRevoked(marker);
        }
        return null;
      };
      const exactPredecessor = (snapshot, proposal) => {
        if (proposal.operation === "register") return null;
        const predecessor = exactBinding(snapshot, {
          deviceId: record.deviceId, publicKey: record.publicKey,
          acceptedBinding: record.acceptedBinding
        });
        if (!predecessor) unavailable();
        return predecessor;
      };
      const submitAuthorization = async (
        proposal,
        currentBinding,
        { pendingAuthorization, expiredExactReplay = false } = {}
      ) => {
        const controller = new AbortController();
        requestController = controller;
        try {
          const result = await authorizeBinding(
            {
              subject,
              proposal,
              ...(pendingAuthorization === undefined ? {} : expiredExactReplay
                ? { expiredPendingAuthorization: pendingAuthorization }
                : { pendingAuthorization })
            },
            {
              signer: pendingAuthorization === undefined ? authorizationSigner : undefined,
              fetchImpl,
              cryptoImpl,
              now,
              signal: controller.signal,
              async persistPending(value) {
                check();
                await write({
                  ...record,
                  pendingAuthorization: value,
                  pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
                  state: pendingState(proposal.operation)
                });
                if (canonicalMessagingDeviceJson(record.pendingAuthorization) !==
                  canonicalMessagingDeviceJson(value)) unavailable();
              }
            }
          );
          check();
          const accepted = authorizedResult(result, proposal, currentBinding, now());
          const fresh = await readSnapshot();
          if (proposal.operation === "revoke") {
            if (relatedBindings(fresh, record.deviceId, record.publicKey).length !== 0) unavailable();
            return finalizeRevoked(accepted.marker);
          }
          const target = proposal.operation === "rotate"
            ? { deviceId: record.deviceId, publicKey: record.rotation.publicKey,
                bindingId: accepted.accepted.bindingId }
            : proposal.operation === "adopt"
              ? { deviceId: record.deviceId, publicKey: record.publicKey,
                  bindingId: proposal.bindingId, acceptedBinding: record.acceptedBinding }
              : { deviceId: record.deviceId, publicKey: record.publicKey,
                  bindingId: accepted.accepted.bindingId };
          const binding = exactBinding(fresh, target);
          if (!binding || !sameMetadata(binding, accepted.accepted)) unavailable();
          return finalizeReady(binding, accepted.marker, {
            promoteRotation: proposal.operation === "rotate"
          });
        } catch {
          if (generation !== epoch) return view;
          await session();
          return publish(record?.state ?? pendingState(proposal.operation));
        } finally {
          if (requestController === controller) requestController = null;
        }
      };
      try {
        subject = context();
        publish(view.state, true);
        await session();
        const stored = await store.read();
        check();
        record = stored === undefined ? undefined : localRecord(stored, subject, CryptoKeyImpl);
        let current = await readSnapshot();

        if (!authorizationEnabled) {
          if (record === undefined) {
            if (explicitAction !== "register") return publish("not-configured");
            const key = await generateKeyMaterial();
            record = extended({
              schema: LOCAL_SCHEMA, version: 1, subject,
              deviceId: randomId(), privateKey: key.privateKey, publicKey: key.publicKey,
              requestId: randomId(), state: "pending-register", acceptedBinding: null
            });
            await session();
            await store.create(record);
            record = await readBack();
            await session();
          }
          const binding = exactBinding(current, {
            deviceId: record.deviceId, publicKey: record.publicKey,
            acceptedBinding: record.acceptedBinding
          });
          if (binding) {
            await write({
              ...record,
              pendingAuthorization: null,
              pendingProposal: null,
              state: "ready",
              acceptedBinding: acceptedMetadata(binding)
            });
            return publish("ready");
          }
          if (record.state === "ready" || record.acceptedBinding) unavailable();
          const command = {
            schema: PREFIX + "command.v1", version: 1, operation: "register",
            deviceId: record.deviceId, algorithm: "x25519-v1", publicKey: record.publicKey,
            expectedBindingId: null, requestId: record.requestId
          };
          let result;
          try { result = await request(ROUTE, command); }
          catch { await session(); return publish("pending-register"); }
          let accepted;
          try { accepted = legacyRegisterResult(result, record, now()); }
          catch { return publish("pending-register"); }
          await write({ ...record, acceptedBinding: accepted });
          current = await readSnapshot();
          const confirmed = exactBinding(current, {
            deviceId: record.deviceId, publicKey: record.publicKey,
            acceptedBinding: accepted
          });
          if (!confirmed) unavailable();
          await write({ ...record, pendingAuthorization: null, pendingProposal: null, state: "ready" });
          return publish("ready");
        }

        if (record === undefined) {
          if (explicitAction !== "register") return publish("not-configured");
          const key = await generateKeyMaterial();
          record = extended({
            schema: LOCAL_SCHEMA, version: 1, subject,
            deviceId: randomId(), privateKey: key.privateKey, publicKey: key.publicKey,
            requestId: randomId(), state: "pending-register", acceptedBinding: null
          });
          record.pendingProposal = canonicalMessagingDeviceAuthorizationProposal({
            deviceId: record.deviceId,
            expectedBindingId: null,
            operation: "register",
            publicKey: record.publicKey,
            requestId: record.requestId
          });
          await session();
          await store.create(record);
          record = await readBack();
          await session();
          publish("pending-register", true);
        }

        if (record.pendingProposal !== null) {
          const proposal = proposalForPending();
          let checked = null;
          if (record.pendingAuthorization !== null) {
            checked = await parseAuthorizationRetry(
              record.pendingAuthorization,
              { subject, proposal },
              { cryptoImpl, now, allowExpiredExactReplay: true }
            );
            const finalized = await reconcileRetainedAuthorization(current, proposal, checked);
            if (finalized !== null) return finalized;
          }
          const continuesUnsignedInitialAction = record.pendingAuthorization === null &&
            explicitAction === (proposal.operation === "adopt" ? "adopt" : proposal.operation);
          if (explicitAction !== "retry" && !continuesUnsignedInitialAction) {
            return publish(record.state);
          }
          const predecessor = exactPredecessor(current, proposal);
          const fresh = checked !== null && Math.floor(now() / 1000) < checked.expiresAt;
          return submitAuthorization(proposal, predecessor, {
            pendingAuthorization: checked === null ? undefined : record.pendingAuthorization,
            expiredExactReplay: checked !== null && !fresh
          });
        }

        // Compatibility recovery for a pre-fix revoke that persisted only its
        // state. New transitions always persist the canonical proposal first.
        if (record.state === "pending-revoke") {
          if (explicitAction !== "retry") return publish("pending-revoke");
          const predecessor = exactBinding(current, {
            deviceId: record.deviceId, publicKey: record.publicKey,
            acceptedBinding: record.acceptedBinding
          });
          if (!predecessor) unavailable();
          const proposal = {
            deviceId: record.deviceId,
            expectedBindingId: predecessor.bindingId,
            operation: "revoke",
            publicKey: null,
            requestId: randomId(record.requestId)
          };
          await write({
            ...record,
            pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal)
          });
          return submitAuthorization(proposal, predecessor);
        }

        if (record.state === "revoked") {
          if (relatedBindings(current, record.deviceId, record.publicKey).length !== 0) unavailable();
          return publish("revoked");
        }
        const binding = exactBinding(current, {
          deviceId: record.deviceId,
          publicKey: record.publicKey,
          acceptedBinding: record.acceptedBinding
        });
        if (binding) {
          const authorized = record.authorization !== null &&
            record.authorization.bindingId === binding.bindingId &&
            ["register", "adopt", "rotate"].includes(record.authorization.action);
          if (!authorized) {
            if (record.state !== "authorization-required" ||
                !record.acceptedBinding || !sameMetadata(record.acceptedBinding, binding)) {
              await write({ ...record, acceptedBinding: acceptedMetadata(binding),
                state: "authorization-required" });
            }
            if (explicitAction !== "adopt") return publish("authorization-required");
            const proposal = {
              bindingId: binding.bindingId,
              operation: "adopt",
              requestId: randomId(record.requestId)
            };
            await write({
              ...record,
              pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
              state: "pending-adopt"
            });
            return submitAuthorization(proposal, binding);
          }
          if (record.state !== "ready") await write({
            ...record, pendingAuthorization: null, pendingProposal: null, state: "ready"
          });
          if (explicitAction === null) return publish("ready");
          if (explicitAction === "rotate") {
            const key = await generateKeyMaterial();
            const rotation = {
              privateKey: key.privateKey,
              publicKey: key.publicKey,
              requestId: randomId(record.requestId)
            };
            const proposal = {
              deviceId: record.deviceId,
              expectedBindingId: binding.bindingId,
              operation: "rotate",
              publicKey: rotation.publicKey,
              requestId: rotation.requestId
            };
            await write({
              ...record,
              rotation,
              pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
              state: "pending-rotate"
            });
            return submitAuthorization(proposal, binding);
          }
          if (explicitAction === "revoke") {
            const proposal = {
              deviceId: record.deviceId,
              expectedBindingId: binding.bindingId,
              operation: "revoke",
              publicKey: null,
              requestId: randomId(record.requestId)
            };
            record = await write({
              ...record,
              pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
              state: "pending-revoke"
            });
            return submitAuthorization(proposal, binding);
          }
          return publish("ready");
        }
        if (record.state === "ready" || record.acceptedBinding) unavailable();
        if (explicitAction !== "register") return publish("pending-register");
        const proposal = {
          deviceId: record.deviceId,
          expectedBindingId: null,
          operation: "register",
          publicKey: record.publicKey,
          requestId: record.requestId
        };
        return submitAuthorization(proposal, null);
      } catch {
        if (epoch === generation) return publish("unavailable");
        return view;
      }
    })().finally(() => { running = null; });
    return running;
  };
  return Object.freeze({
    reconcile: () => run(null),
    setup: () => run("register"),
    adopt: () => run("adopt"),
    rotate: () => run("rotate"),
    revoke: () => run("revoke"),
    retry: () => run("retry"),
    view: () => view,
    cancel: () => { generation += 1; requestController?.abort(); publish("unavailable"); }
  });
}
