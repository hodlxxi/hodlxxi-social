// Dormant browser-local Enrollment V2 prerequisite. No runtime entrypoint imports
// this module, and possession of this key is not an active UBID association.
export const MESSAGING_DEVICE_ED25519_KEY_RUNTIME_ENABLED = false;

const DATABASE_NAME = "hodlxxi-social-messaging-device-ed25519-key-v1";
const STORE_NAME = "authentication-key";
const STORE_KEY = "current";
const LOCAL_SCHEMA = "hodlxxi.social_messaging_device_ed25519_key_local.v1";
const PUBLIC_SCHEMA =
  "hodlxxi.social_messaging_device_ed25519_key_public.v1";
const PROFILE =
  "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1";
const ENROLLMENT_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment.v2";
const ENROLLMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2";
const ENROLLMENT_PROOF_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment_proof.v2";
const ENROLLMENT_PROOF_PREIMAGE_SCHEMA =
  "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2";
const ENROLLMENT_PROOF_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2";
const X25519_COMMITMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1";
const ENROLLMENT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2";
const MAX_ENROLLMENT_BYTES = 4096;
const MAX_ENROLLMENT_LIFETIME_MS = 60_000;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const X25519_COMMITMENT =
  /^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/;
const ENROLLMENT_FIELDS = [
  "audience", "deviceId", "domain", "ed25519PublicKey",
  "enrollmentChallengeId", "expiresAt", "issuedAt", "profile", "schema",
  "subject", "version", "x25519BindingId", "x25519BindingVersion",
  "x25519PublicKeyCommitment"
];
const LOCAL_FIELDS = [
  "schema", "version", "subject", "deviceId", "x25519BindingId",
  "x25519BindingVersion", "x25519PublicKeyCommitment",
  "ed25519PublicKey", "privateKey"
];
const encoder = new TextEncoder();
const unavailable = () => {
  throw new Error("messaging device authentication key unavailable");
};
const canonical = (value) => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]))
);
const isHex64 = (value) =>
  typeof value === "string" && HEX64.test(value);
const isInteger = (value) =>
  Number.isSafeInteger(value) && value >= 0;
const validBindingVersion = (value) =>
  Number.isInteger(value) && value >= 1 && value <= 1024;
const hexBytes = (bytes) => Array.from(
  bytes,
  (byte) => byte.toString(16).padStart(2, "0")
).join("");

function plainData(value, required, exact = false) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string") ||
    required.some((field) =>
      !descriptors[field]?.enumerable ||
      !Object.hasOwn(descriptors[field], "value")
    ) ||
    (exact && (
      keys.length !== required.length ||
      keys.some((key) => !required.includes(key))
    ))
  ) unavailable();
  return Object.fromEntries(
    required.map((field) => [field, descriptors[field].value])
  );
}

function privateSigningKey(key, CryptoKeyImpl) {
  if (
    typeof CryptoKeyImpl !== "function" || !(key instanceof CryptoKeyImpl) ||
    key.type !== "private" || key.extractable !== false ||
    key.algorithm?.name !== "Ed25519" || key.usages.length !== 1 ||
    key.usages[0] !== "sign"
  ) unavailable();
}

function publicVerificationKey(key, CryptoKeyImpl) {
  if (
    typeof CryptoKeyImpl !== "function" || !(key instanceof CryptoKeyImpl) ||
    key.type !== "public" || key.extractable !== true ||
    key.algorithm?.name !== "Ed25519" || key.usages.length !== 1 ||
    key.usages[0] !== "verify"
  ) unavailable();
}

function localRecord(value, subject, CryptoKeyImpl) {
  const record = plainData(value, LOCAL_FIELDS, true);
  if (
    record.schema !== LOCAL_SCHEMA || record.version !== 1 ||
    !isHex64(record.subject) || record.subject !== subject ||
    !isHex64(record.deviceId) || !isHex64(record.x25519BindingId) ||
    !validBindingVersion(record.x25519BindingVersion) ||
    typeof record.x25519PublicKeyCommitment !== "string" ||
    !X25519_COMMITMENT.test(record.x25519PublicKeyCommitment) ||
    !isHex64(record.ed25519PublicKey) ||
    record.ed25519PublicKey === record.subject
  ) unavailable();
  privateSigningKey(record.privateKey, CryptoKeyImpl);
  return record;
}

function publicRecord(record) {
  return Object.freeze({
    schema: PUBLIC_SCHEMA,
    version: 1,
    subject: record.subject,
    deviceId: record.deviceId,
    x25519BindingId: record.x25519BindingId,
    x25519BindingVersion: record.x25519BindingVersion,
    x25519PublicKeyCommitment: record.x25519PublicKeyCommitment,
    ed25519PublicKey: record.ed25519PublicKey
  });
}

function sameLocalIdentity(left, right) {
  return [
    "subject", "deviceId", "x25519BindingId", "x25519BindingVersion",
    "x25519PublicKeyCommitment", "ed25519PublicKey"
  ].every((field) => left[field] === right[field]);
}

function currentContext(getContext) {
  const value = plainData(getContext?.(), ["access", "subject"]);
  if (value.access !== "full" || !isHex64(value.subject)) unavailable();
  return value.subject;
}

function x25519Binding(value, subject, now) {
  const record = plainData(value, [
    "subject", "deviceId", "publicKey", "state", "acceptedBinding"
  ]);
  const accepted = plainData(record.acceptedBinding, [
    "bindingId", "version", "validFrom", "expiresAt"
  ], true);
  if (
    record.subject !== subject || record.state !== "ready" ||
    !isHex64(record.deviceId) || !isHex64(record.publicKey) ||
    !isHex64(accepted.bindingId) || !validBindingVersion(accepted.version) ||
    !isInteger(accepted.validFrom) || !isInteger(accepted.expiresAt) ||
    !isInteger(now) || now < accepted.validFrom || now >= accepted.expiresAt
  ) unavailable();
  return Object.freeze({
    subject,
    deviceId: record.deviceId,
    publicKey: record.publicKey,
    x25519BindingId: accepted.bindingId,
    x25519BindingVersion: accepted.version
  });
}

// Frozen HTTPS-origin grammar shared with the server verifier. It validates
// exact bytes and never normalizes the Enrollment V2 audience.
function canonicalAudience(value) {
  if (
    typeof value !== "string" || value.length === 0 || value.length > 255 ||
    /[^\x21-\x7e]/.test(value)
  ) return false;
  const match = /^https:\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]+))?$/.exec(value);
  if (!match) return false;
  const [, host, port] = match;
  if (
    port !== undefined &&
    (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535 || port === "443")
  ) return false;
  if (host.startsWith("[")) {
    try { return new URL(value).hostname === host; } catch { return false; }
  }
  const labels = host.split(".");
  if (labels.length === 4 && labels.every((label) => /^[0-9]+$/.test(label))) {
    return labels.every((label) =>
      /^(0|[1-9][0-9]{0,2})$/.test(label) && Number(label) <= 255
    );
  }
  if (/^(?:[0-9]+|0x[0-9a-f]*)$/.test(labels.at(-1))) return false;
  return labels.every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) &&
    !label.startsWith("xn--")
  );
}

function enrollment(source) {
  if (
    typeof source !== "string" || source.length === 0 ||
    encoder.encode(source).byteLength > MAX_ENROLLMENT_BYTES ||
    /[^\x20-\x7e]/.test(source)
  ) unavailable();
  let parsed;
  try { parsed = JSON.parse(source); } catch { unavailable(); }
  const value = plainData(parsed, ENROLLMENT_FIELDS, true);
  if (
    canonical(value) !== source || value.schema !== ENROLLMENT_SCHEMA ||
    value.version !== 2 || value.domain !== ENROLLMENT_DOMAIN ||
    value.profile !== PROFILE || !canonicalAudience(value.audience) ||
    !isHex64(value.subject) || !isHex64(value.deviceId) ||
    !isHex64(value.x25519BindingId) ||
    !validBindingVersion(value.x25519BindingVersion) ||
    typeof value.x25519PublicKeyCommitment !== "string" ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment) ||
    !isHex64(value.ed25519PublicKey) ||
    value.ed25519PublicKey === value.subject ||
    !isHex64(value.enrollmentChallengeId) ||
    !isInteger(value.issuedAt) || !isInteger(value.expiresAt) ||
    value.expiresAt <= value.issuedAt ||
    value.expiresAt - value.issuedAt > MAX_ENROLLMENT_LIFETIME_MS
  ) unavailable();
  return Object.freeze(value);
}

function enrollmentPreimage(source, value) {
  return canonical({
    domain: ENROLLMENT_PROOF_DOMAIN,
    enrollment: source,
    profile: PROFILE,
    publicKey: value.ed25519PublicKey,
    schema: ENROLLMENT_PROOF_PREIMAGE_SCHEMA,
    version: 2
  });
}

function createStore(indexedDBImpl) {
  const open = () => new Promise((resolve, reject) => {
    const factory = indexedDBImpl === undefined
      ? globalThis.indexedDB : indexedDBImpl;
    if (typeof factory?.open !== "function") {
      reject(new Error("messaging device authentication key unavailable"));
      return;
    }
    const request = factory.open(DATABASE_NAME, 1);
    let blocked = false;
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onerror = () =>
      reject(new Error("messaging device authentication key unavailable"));
    request.onblocked = () => {
      blocked = true;
      reject(new Error("messaging device authentication key unavailable"));
    };
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
            ? db.transaction(STORE_NAME, mode, { durability: "strict" })
            : db.transaction(STORE_NAME, mode);
          if (mode === "readwrite" && tx.durability !== "strict") {
            tx.abort();
            unavailable();
          }
          let result;
          tx.oncomplete = () => resolve(result);
          tx.onabort = tx.onerror = () => reject(
            new Error("messaging device authentication key unavailable")
          );
          action(tx.objectStore(STORE_NAME), (value) => { result = value; });
        } catch {
          try { tx?.abort(); } catch {}
          reject(new Error("messaging device authentication key unavailable"));
        }
      });
    } finally { db.close(); }
  };
  return Object.freeze({
    read: () => transaction("readonly", (store, done) => {
      const request = store.get(STORE_KEY);
      request.onsuccess = () => done(request.result);
    }),
    create: (record) => transaction("readwrite", (store) => {
      store.add(record, STORE_KEY);
    })
  });
}

async function sha256Hex(cryptoImpl, domain, source) {
  if (typeof cryptoImpl?.subtle?.digest !== "function") unavailable();
  const bytes = encoder.encode(`${domain}\0${source}`);
  const result = await cryptoImpl.subtle.digest("SHA-256", bytes);
  if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) unavailable();
  return hexBytes(new Uint8Array(result));
}

/**
 * Creates an explicitly-instantiated, browser-local Enrollment V2 key boundary.
 * It has no request-signing or arbitrary-signing operation.
 */
export function createMessagingDeviceEd25519KeyV1({
  getContext,
  readX25519Binding,
  indexedDBImpl,
  cryptoImpl = globalThis.crypto,
  CryptoKeyImpl = globalThis.CryptoKey,
  now = Date.now
} = {}) {
  const store = createStore(indexedDBImpl);
  const check = (subject) => {
    if (currentContext(getContext) !== subject) unavailable();
  };
  const readBinding = async (subject) => {
    check(subject);
    if (typeof readX25519Binding !== "function") unavailable();
    const value = await readX25519Binding();
    check(subject);
    return x25519Binding(value, subject, now());
  };
  const commitment = async (binding, subject) => {
    const value = "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
      await sha256Hex(cryptoImpl, X25519_COMMITMENT_DOMAIN, binding.publicKey);
    check(subject);
    return value;
  };
  const readStored = async (subject) => {
    check(subject);
    const raw = await store.read();
    check(subject);
    return raw === undefined ? undefined : localRecord(raw, subject, CryptoKeyImpl);
  };
  const matchingStored = (record, binding, x25519PublicKeyCommitment) => {
    if (
      record === undefined ||
      record.deviceId !== binding.deviceId ||
      record.x25519BindingId !== binding.x25519BindingId ||
      record.x25519BindingVersion !== binding.x25519BindingVersion ||
      record.x25519PublicKeyCommitment !== x25519PublicKeyCommitment
    ) unavailable();
    return record;
  };
  const prepare = async () => {
    const subject = currentContext(getContext);
    const binding = await readBinding(subject);
    const x25519PublicKeyCommitment = await commitment(binding, subject);
    const existing = await readStored(subject);
    if (existing !== undefined) {
      return publicRecord(matchingStored(
        existing,
        binding,
        x25519PublicKeyCommitment
      ));
    }
    if (
      typeof cryptoImpl?.subtle?.generateKey !== "function" ||
      typeof cryptoImpl.subtle.exportKey !== "function"
    ) unavailable();
    const pair = await cryptoImpl.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"]
    );
    check(subject);
    privateSigningKey(pair?.privateKey, CryptoKeyImpl);
    publicVerificationKey(pair?.publicKey, CryptoKeyImpl);
    const rawPublicKey = await cryptoImpl.subtle.exportKey("raw", pair.publicKey);
    check(subject);
    if (!(rawPublicKey instanceof ArrayBuffer) || rawPublicKey.byteLength !== 32) {
      unavailable();
    }
    const record = {
      schema: LOCAL_SCHEMA,
      version: 1,
      subject,
      deviceId: binding.deviceId,
      x25519BindingId: binding.x25519BindingId,
      x25519BindingVersion: binding.x25519BindingVersion,
      x25519PublicKeyCommitment,
      ed25519PublicKey: hexBytes(new Uint8Array(rawPublicKey)),
      privateKey: pair.privateKey
    };
    localRecord(record, subject, CryptoKeyImpl);
    try { await store.create(record); } catch {
      check(subject);
      const winner = await readStored(subject);
      if (winner === undefined) unavailable();
      return publicRecord(matchingStored(
        winner,
        binding,
        x25519PublicKeyCommitment
      ));
    }
    check(subject);
    const stored = await readStored(subject);
    if (stored === undefined || !sameLocalIdentity(stored, record)) unavailable();
    return publicRecord(matchingStored(
      stored,
      binding,
      x25519PublicKeyCommitment
    ));
  };
  const createEnrollmentProofV2 = async (enrollmentWire) => {
    const subject = currentContext(getContext);
    const value = enrollment(enrollmentWire);
    const currentNow = now();
    if (
      value.subject !== subject || !isInteger(currentNow) ||
      currentNow < value.issuedAt || currentNow >= value.expiresAt
    ) unavailable();
    const binding = await readBinding(subject);
    const x25519PublicKeyCommitment = await commitment(binding, subject);
    const record = matchingStored(
      await readStored(subject),
      binding,
      x25519PublicKeyCommitment
    );
    if (
      value.deviceId !== record.deviceId ||
      value.x25519BindingId !== record.x25519BindingId ||
      value.x25519BindingVersion !== record.x25519BindingVersion ||
      value.x25519PublicKeyCommitment !== record.x25519PublicKeyCommitment ||
      value.ed25519PublicKey !== record.ed25519PublicKey
    ) unavailable();
    const enrollmentDigest =
      "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
      await sha256Hex(cryptoImpl, ENROLLMENT_DIGEST_DOMAIN, enrollmentWire);
    check(subject);
    if (typeof cryptoImpl?.subtle?.sign !== "function") unavailable();
    const preimage = enrollmentPreimage(enrollmentWire, value);
    const signature = await cryptoImpl.subtle.sign(
      { name: "Ed25519" },
      record.privateKey,
      encoder.encode(preimage)
    );
    check(subject);
    if (!(signature instanceof ArrayBuffer) || signature.byteLength !== 64) {
      unavailable();
    }
    const afterBinding = await readBinding(subject);
    const afterCommitment = await commitment(afterBinding, subject);
    const afterRecord = matchingStored(
      await readStored(subject),
      afterBinding,
      afterCommitment
    );
    if (!sameLocalIdentity(record, afterRecord)) unavailable();
    const finishedAt = now();
    if (
      !isInteger(finishedAt) || finishedAt < value.issuedAt ||
      finishedAt >= value.expiresAt
    ) unavailable();
    const proof = canonical({
      algorithm: "Ed25519",
      enrollmentChallengeId: value.enrollmentChallengeId,
      enrollmentDigest,
      profile: PROFILE,
      publicKey: value.ed25519PublicKey,
      schema: ENROLLMENT_PROOF_SCHEMA,
      signature: hexBytes(new Uint8Array(signature)),
      version: 2
    });
    const parsed = JSON.parse(proof);
    if (
      canonical(parsed) !== proof || !HEX128.test(parsed.signature) ||
      parsed.publicKey !== afterRecord.ed25519PublicKey
    ) unavailable();
    return proof;
  };
  return Object.freeze({ prepare, createEnrollmentProofV2 });
}
