// Dormant browser-local provisional key boundary for pre-enrollment V2. This
// store is intentionally unrelated to the accepted-binding V1 key store.
import {
  canonicalMessagingDeviceAuthorizationProposal,
  canonicalMessagingDeviceJson as canonical,
  inspectMessagingDeviceAuthorizationClaim
} from "./messaging-device-authorization-v1.mjs";
import {
  MESSAGING_DEVICE_DATABASE_NAME,
  MESSAGING_DEVICE_DEVICE_STORE_NAME,
  MESSAGING_DEVICE_PROVISIONAL_AUTHENTICATION_STORE_V2,
  MESSAGING_DEVICE_SHARED_DATABASE_VERSION_V2,
  projectExactPendingMessagingDeviceRegister
} from "./messaging-device-v128c1.mjs";
import {
  authorizationDigestV2,
  parseAuthorizationEnvelopeV2,
  parseSignedAttemptV2,
  preEnrollmentDigestV2
} from "./mobile-device-authorization-contract-v2.mjs";

export const MESSAGING_DEVICE_ED25519_KEY_V2_RUNTIME_ENABLED = false;

const DATABASE_NAME = MESSAGING_DEVICE_DATABASE_NAME;
const DATABASE_VERSION = MESSAGING_DEVICE_SHARED_DATABASE_VERSION_V2;
const DEVICE_STORE_NAME = MESSAGING_DEVICE_DEVICE_STORE_NAME;
const STORE_NAME = MESSAGING_DEVICE_PROVISIONAL_AUTHENTICATION_STORE_V2;
const LOCAL_SCHEMA =
  "hodlxxi.social_messaging_device_ed25519_provisional_key_local.v2";
const PUBLIC_SCHEMA =
  "hodlxxi.social_messaging_device_ed25519_provisional_key_public.v2";
const SIGNING_CLAIM_SCHEMA =
  "hodlxxi.social_messaging_device_pre_enrollment_signing_claim.v2";
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
const ENROLLMENT_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2";
const X25519_COMMITMENT_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1";
const KEY_RELATION_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_KEY_RELATION_V2";
const MAX_ENROLLMENT_BYTES = 4_096;
const MAX_ENROLLMENT_LIFETIME_MS = 60_000;
const MAX_CLAIM_BYTES = 24_576;
const MAX_SIGNED_ATTEMPT_BYTES = 32_768;
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
  "bindingAuthorizationContent", "bindingAuthorizationDigest", "deviceId",
  "ed25519PublicKey", "pendingProposal", "privateKey", "recordRevision",
  "requestId", "schema", "signedAttempt", "signingClaim", "state",
  "subjectHint", "version", "x25519BindingId", "x25519BindingVersion",
  "x25519PublicKey", "x25519PublicKeyCommitment"
];
const CLAIM_FIELDS = [
  "authorizationDigest", "authorizationWire", "deviceId",
  "ed25519PublicKey", "pairingId", "preEnrollmentDigest", "recordRevision",
  "requestId", "schema", "state", "subject", "version",
  "x25519BindingId", "x25519BindingVersion", "x25519PublicKeyCommitment"
];
const encoder = new TextEncoder();
const unavailable = () => {
  throw new Error("messaging device provisional authentication key unavailable");
};
const isHex64 = (value) => typeof value === "string" && HEX64.test(value);
const toHex = (value) => Array.from(
  new Uint8Array(value),
  (byte) => byte.toString(16).padStart(2, "0")
).join("");
const fromHex = (value) => Uint8Array.from(
  value.match(/../g),
  (part) => Number.parseInt(part, 16)
);

function plainData(value, required, exact = false) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) unavailable();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) =>
        typeof key !== "string" ||
        descriptors[key].enumerable !== true ||
        !Object.hasOwn(descriptors[key], "value")
      ) ||
      required.some((field) => !Object.hasOwn(descriptors, field)) ||
      (exact && (
        keys.length !== required.length ||
        keys.some((key) => !required.includes(key))
      ))
    ) unavailable();
    return Object.fromEntries(
      required.map((field) => [field, descriptors[field].value])
    );
  } catch {
    unavailable();
  }
}

function optionalData(value, allowed) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) unavailable();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) =>
      typeof key !== "string" || !allowed.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    )) unavailable();
    return Object.fromEntries(
      allowed.filter((field) => Object.hasOwn(descriptors, field))
        .map((field) => [field, descriptors[field].value])
    );
  } catch {
    unavailable();
  }
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
    key.type !== "public" || key.extractable !== false ||
    key.algorithm?.name !== "Ed25519" || key.usages.length !== 1 ||
    key.usages[0] !== "verify"
  ) unavailable();
}

function currentContext(getContext) {
  const value = plainData(getContext?.(), ["revision", "subjectHint"], true);
  if (!isHex64(value.revision) || !isHex64(value.subjectHint)) unavailable();
  return Object.freeze(value);
}

function pendingX25519(value, subjectHint) {
  const record = plainData(value, [
    "deviceId", "pendingProposal", "publicKey", "requestId", "subject"
  ], true);
  if (
    record.subject !== subjectHint ||
    !isHex64(record.deviceId) || !isHex64(record.publicKey) ||
    record.publicKey === subjectHint || !isHex64(record.requestId) ||
    typeof record.pendingProposal !== "string"
  ) unavailable();
  const expectedProposal = canonicalMessagingDeviceAuthorizationProposal({
    deviceId: record.deviceId,
    expectedBindingId: null,
    operation: "register",
    publicKey: record.publicKey,
    requestId: record.requestId
  });
  if (record.pendingProposal !== expectedProposal) unavailable();
  return Object.freeze({
    subjectHint,
    deviceId: record.deviceId,
    publicKey: record.publicKey,
    requestId: record.requestId,
    pendingProposal: expectedProposal,
    proposal: Object.freeze(JSON.parse(expectedProposal))
  });
}

function samePending(left, right) {
  return left.subject === right.subjectHint && [
    "deviceId", "pendingProposal", "publicKey", "requestId"
  ].every((field) => left[field] === right[field]);
}

// Frozen HTTPS-origin grammar shared byte-for-byte in behavior with the V1
// browser boundary and server verifier. It validates and never normalizes.
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

function parseEnrollment(source) {
  if (
    typeof source !== "string" || source.length === 0 ||
    source.length > MAX_ENROLLMENT_BYTES || /[^\x20-\x7e]/.test(source) ||
    encoder.encode(source).byteLength > MAX_ENROLLMENT_BYTES
  ) unavailable();
  let parsed;
  try { parsed = JSON.parse(source); } catch { unavailable(); }
  const value = plainData(parsed, ENROLLMENT_FIELDS, true);
  if (
    canonical(value) !== source || value.schema !== ENROLLMENT_SCHEMA ||
    value.version !== 2 || value.domain !== ENROLLMENT_DOMAIN ||
    value.profile !== PROFILE || !canonicalAudience(value.audience) ||
    !isHex64(value.subject) ||
    !isHex64(value.deviceId) || !isHex64(value.x25519BindingId) ||
    value.x25519BindingVersion !== 1 ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment) ||
    !isHex64(value.ed25519PublicKey) ||
    value.ed25519PublicKey === value.subject ||
    !isHex64(value.enrollmentChallengeId) ||
    !Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0 ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= value.issuedAt ||
    value.expiresAt - value.issuedAt > MAX_ENROLLMENT_LIFETIME_MS
  ) unavailable();
  return Object.freeze(value);
}

function publicRecord(record) {
  return Object.freeze({
    schema: PUBLIC_SCHEMA,
    version: 2,
    state: "prepared-provisional",
    subjectHint: record.subjectHint,
    deviceId: record.deviceId,
    requestId: record.requestId,
    x25519BindingId: record.x25519BindingId,
    x25519BindingVersion: record.x25519BindingVersion,
    x25519PublicKeyCommitment: record.x25519PublicKeyCommitment,
    ed25519PublicKey: record.ed25519PublicKey,
    recordRevision: record.recordRevision
  });
}

function localRecord(value, subjectHint, CryptoKeyImpl) {
  const record = plainData(value, LOCAL_FIELDS, true);
  if (
    record.schema !== LOCAL_SCHEMA || record.version !== 2 ||
    record.state !== "prepared-provisional" ||
    record.subjectHint !== subjectHint || !isHex64(record.subjectHint) ||
    !isHex64(record.deviceId) || !isHex64(record.requestId) ||
    !isHex64(record.x25519PublicKey) ||
    typeof record.pendingProposal !== "string" ||
    typeof record.bindingAuthorizationContent !== "string" ||
    !isHex64(record.bindingAuthorizationDigest) ||
    !isHex64(record.x25519BindingId) ||
    record.x25519BindingVersion !== 1 ||
    !X25519_COMMITMENT.test(record.x25519PublicKeyCommitment) ||
    !isHex64(record.ed25519PublicKey) ||
    record.ed25519PublicKey === record.subjectHint ||
    !isHex64(record.recordRevision) ||
    !(record.signingClaim === null || (
      typeof record.signingClaim === "string" &&
      record.signingClaim.length <= MAX_CLAIM_BYTES
    )) ||
    !(record.signedAttempt === null || (
      typeof record.signedAttempt === "string" &&
      record.signedAttempt.length <= MAX_SIGNED_ATTEMPT_BYTES
    ))
  ) unavailable();
  privateSigningKey(record.privateKey, CryptoKeyImpl);
  return record;
}

function sameIdentity(left, right) {
  return [
    "bindingAuthorizationContent", "bindingAuthorizationDigest", "deviceId",
    "ed25519PublicKey", "pendingProposal", "recordRevision", "requestId",
    "schema", "state", "subjectHint", "version", "x25519BindingId",
    "x25519BindingVersion",
    "x25519PublicKey", "x25519PublicKeyCommitment"
  ].every((field) => left[field] === right[field]);
}

function exactOutOfLineStore(store) {
  if (
    store?.keyPath !== null || store.autoIncrement !== false ||
    Array.from(store.indexNames).length !== 0
  ) unavailable();
  return store;
}

function createStore(indexedDBImpl) {
  const open = () => new Promise((resolve, reject) => {
    try {
      const factory = indexedDBImpl === undefined
        ? globalThis.indexedDB : indexedDBImpl;
      if (typeof factory?.open !== "function") unavailable();
      const request = factory.open(DATABASE_NAME, DATABASE_VERSION);
      let blocked = false;
      request.onupgradeneeded = (event) => {
        if (blocked) {
          try { request.transaction?.abort(); } catch {}
          return;
        }
        try {
          const db = request.result;
          const oldVersion = event?.oldVersion;
          const names = Array.from(db.objectStoreNames);
          if (oldVersion === 0) {
            if (names.length !== 0) unavailable();
            exactOutOfLineStore(db.createObjectStore(DEVICE_STORE_NAME));
            exactOutOfLineStore(db.createObjectStore(STORE_NAME));
          } else if (oldVersion === 1) {
            if (names.length !== 1 || names[0] !== DEVICE_STORE_NAME) {
              unavailable();
            }
            exactOutOfLineStore(
              request.transaction.objectStore(DEVICE_STORE_NAME)
            );
            exactOutOfLineStore(db.createObjectStore(STORE_NAME));
          } else {
            unavailable();
          }
        } catch {
          try { request.transaction?.abort(); } catch {}
        }
      };
      request.onerror = () => reject(
        new Error("messaging device provisional authentication key unavailable")
      );
      request.onblocked = () => {
        blocked = true;
        reject(new Error(
          "messaging device provisional authentication key unavailable"
        ));
      };
      request.onsuccess = () => {
        const db = request.result;
        try {
          if (blocked) { db.close(); return; }
          const names = Array.from(db.objectStoreNames);
          if (
            db.version !== DATABASE_VERSION || names.length !== 2 ||
            !names.includes(DEVICE_STORE_NAME) || !names.includes(STORE_NAME)
          ) unavailable();
          const metadata = db.transaction(
            [DEVICE_STORE_NAME, STORE_NAME],
            "readonly"
          );
          exactOutOfLineStore(metadata.objectStore(DEVICE_STORE_NAME));
          exactOutOfLineStore(metadata.objectStore(STORE_NAME));
          db.onversionchange = () => db.close();
          resolve(db);
        } catch {
          try { db.close(); } catch {}
          reject(new Error(
            "messaging device provisional authentication key unavailable"
          ));
        }
      };
    } catch {
      reject(new Error("messaging device provisional authentication key unavailable"));
    }
  });
  const transaction = async (storeNames, mode, action) => {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        let tx;
        try {
          tx = mode === "readwrite"
            ? db.transaction(storeNames, mode, { durability: "strict" })
            : db.transaction(storeNames, mode);
          if (mode === "readwrite" && tx.durability !== "strict") {
            tx.abort();
            unavailable();
          }
          let result;
          tx.oncomplete = () => resolve(result);
          tx.onabort = tx.onerror = () => reject(
            new Error("messaging device provisional authentication key unavailable")
          );
          action(
            (name) => tx.objectStore(name),
            (value) => { result = value; },
            tx
          );
        } catch {
          try { tx?.abort(); } catch {}
          reject(new Error("messaging device provisional authentication key unavailable"));
        }
      });
    } finally {
      db.close();
    }
  };
  return Object.freeze({
    readPending: (subject, CryptoKeyImpl) => transaction(
      DEVICE_STORE_NAME,
      "readonly",
      (objectStore, done, tx) => {
        const request = objectStore(DEVICE_STORE_NAME).get("current");
        request.onsuccess = () => {
          try {
            done(projectExactPendingMessagingDeviceRegister(
              request.result,
              subject,
              CryptoKeyImpl
            ));
          } catch { tx.abort(); }
        };
      }
    ),
    read: (deviceId) => transaction(STORE_NAME, "readonly", (objectStore, done) => {
      const request = objectStore(STORE_NAME).get(deviceId);
      request.onsuccess = () => done(request.result);
    }),
    create: (
      expectedPending,
      record,
      subject,
      CryptoKeyImpl,
      guard
    ) => transaction(
      [DEVICE_STORE_NAME, STORE_NAME],
      "readwrite",
      (objectStore, _done, tx) => {
        const get = objectStore(DEVICE_STORE_NAME).get("current");
        get.onsuccess = () => {
          try {
            const authoritative = projectExactPendingMessagingDeviceRegister(
              get.result,
              subject,
              CryptoKeyImpl
            );
            if (!samePending(authoritative, expectedPending)) unavailable();
            guard();
            objectStore(STORE_NAME).add(record, record.deviceId);
          } catch { tx.abort(); }
        };
      }
    ),
    claim: (
      expectedPending,
      expectedRecord,
      claimWire,
      subject,
      CryptoKeyImpl,
      guard
    ) => transaction(
      [DEVICE_STORE_NAME, STORE_NAME],
      "readwrite",
      (objectStore, done, tx) => {
        const pendingGet = objectStore(DEVICE_STORE_NAME).get("current");
        pendingGet.onsuccess = () => {
          try {
            const authoritative = projectExactPendingMessagingDeviceRegister(
              pendingGet.result,
              subject,
              CryptoKeyImpl
            );
            if (!samePending(authoritative, expectedPending)) unavailable();
            const get = objectStore(STORE_NAME).get(expectedRecord.deviceId);
            get.onsuccess = () => {
              try {
                const record = localRecord(
                  get.result,
                  subject,
                  CryptoKeyImpl
                );
                if (!sameIdentity(record, expectedRecord)) unavailable();
                if (record.signedAttempt !== null) {
                  guard();
                  done(Object.freeze({
                    kind: "signed",
                    wire: record.signedAttempt
                  }));
                  return;
                }
                if (record.signingClaim !== null) {
                  guard();
                  done(Object.freeze({
                    kind: "existing-claim",
                    wire: record.signingClaim
                  }));
                  return;
                }
                const next = { ...record, signingClaim: claimWire };
                guard();
                const put = objectStore(STORE_NAME).put(
                  next,
                  expectedRecord.deviceId
                );
                put.onsuccess = () => {
                  try {
                    guard();
                    done(Object.freeze({
                      kind: "claimed",
                      wire: claimWire
                    }));
                  } catch { tx.abort(); }
                };
              } catch { tx.abort(); }
            };
          } catch { tx.abort(); }
        };
      }
    ),
    persist: (
      deviceId,
      revision,
      claimWire,
      attemptWire,
      expectedRecord,
      subject,
      CryptoKeyImpl
    ) => transaction(
      STORE_NAME,
      "readwrite",
      (objectStore, done, tx) => {
        const get = objectStore(STORE_NAME).get(deviceId);
        get.onsuccess = () => {
          try {
            const record = localRecord(get.result, subject, CryptoKeyImpl);
            if (
              record.recordRevision !== revision ||
              record.signingClaim !== claimWire ||
              !sameIdentity(record, expectedRecord)
            ) unavailable();
            if (record.signedAttempt !== null) {
              if (record.signedAttempt !== attemptWire) unavailable();
              done(record.signedAttempt);
              return;
            }
            const next = { ...record, signedAttempt: attemptWire };
            const put = objectStore(STORE_NAME).put(next, deviceId);
            put.onsuccess = () => done(attemptWire);
          } catch { tx.abort(); }
        };
      }
    )
  });
}

async function sha256Hex(cryptoImpl, domain, source) {
  try {
    const result = await cryptoImpl.subtle.digest(
      "SHA-256",
      encoder.encode(`${domain}\0${source}`)
    );
    if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) unavailable();
    return toHex(result);
  } catch {
    unavailable();
  }
}

function parseSigningClaim(source) {
  if (
    typeof source !== "string" || source.length === 0 ||
    source.length > MAX_CLAIM_BYTES || /[^\x20-\x7e]/.test(source) ||
    encoder.encode(source).byteLength > MAX_CLAIM_BYTES
  ) unavailable();
  let parsed;
  try { parsed = JSON.parse(source); } catch { unavailable(); }
  const value = plainData(parsed, CLAIM_FIELDS, true);
  if (
    canonical(value) !== source || value.schema !== SIGNING_CLAIM_SCHEMA ||
    value.version !== 2 || value.state !== "signing-claimed" ||
    !isHex64(value.authorizationDigest) ||
    typeof value.authorizationWire !== "string" ||
    !isHex64(value.deviceId) || !isHex64(value.ed25519PublicKey) ||
    !isHex64(value.pairingId) ||
    typeof value.preEnrollmentDigest !== "string" ||
    !/^hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:[0-9a-f]{64}$/.test(
      value.preEnrollmentDigest
    ) ||
    !isHex64(value.recordRevision) || !isHex64(value.requestId) ||
    !isHex64(value.subject) || !isHex64(value.x25519BindingId) ||
    value.x25519BindingVersion !== 1 ||
    !X25519_COMMITMENT.test(value.x25519PublicKeyCommitment)
  ) unavailable();
  return Object.freeze(value);
}

/**
 * The returned boundary exposes only exact Enrollment V2 proof and immutable
 * signer-attempt operations. It has no promotion, ready, accepted or general
 * signing operation.
 */
export function createMessagingDeviceEd25519KeyV2(input = {}) {
  let options;
  try {
    options = optionalData(input, [
      "CryptoKeyImpl", "cryptoImpl", "getContext", "indexedDBImpl", "now"
    ]);
  } catch {
    unavailable();
  }
  const {
    getContext,
    indexedDBImpl,
    cryptoImpl = globalThis.crypto,
    CryptoKeyImpl = globalThis.CryptoKey,
    now = Date.now
  } = options;
  const store = createStore(indexedDBImpl);
  const check = (initial) => {
    const current = currentContext(getContext);
    if (
      current.subjectHint !== initial.subjectHint ||
      current.revision !== initial.revision
    ) unavailable();
  };
  const readPending = async (initial) => {
    check(initial);
    const value = await store.readPending(initial.subjectHint, CryptoKeyImpl);
    check(initial);
    return pendingX25519(value, initial.subjectHint);
  };
  const assertPending = async (initial, expected) => {
    const current = await readPending(initial);
    check(initial);
    if (
      current.deviceId !== expected.deviceId ||
      current.publicKey !== expected.publicKey ||
      current.requestId !== expected.requestId ||
      current.pendingProposal !== expected.pendingProposal
    ) unavailable();
    return current;
  };
  const readStored = async (initial, deviceId) => {
    check(initial);
    const raw = await store.read(deviceId);
    check(initial);
    return raw === undefined
      ? undefined : localRecord(raw, initial.subjectHint, CryptoKeyImpl);
  };
  const validateRelationship = async (record, initial, pending) => {
    check(initial);
    if (typeof cryptoImpl?.subtle?.importKey !== "function" ||
        typeof cryptoImpl.subtle.sign !== "function" ||
        typeof cryptoImpl.subtle.verify !== "function") unavailable();
    const publicKey = await cryptoImpl.subtle.importKey(
      "raw",
      fromHex(record.ed25519PublicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    check(initial);
    publicVerificationKey(publicKey, CryptoKeyImpl);
    await assertPending(initial, pending);
    check(initial);
    const message = encoder.encode(canonical({
      deviceId: record.deviceId,
      domain: KEY_RELATION_DOMAIN,
      publicKey: record.ed25519PublicKey,
      recordRevision: record.recordRevision,
      requestId: record.requestId,
      subject: record.subjectHint,
      version: 2
    }));
    const signature = await cryptoImpl.subtle.sign(
      { name: "Ed25519" },
      record.privateKey,
      message
    );
    check(initial);
    if (!(signature instanceof ArrayBuffer) || signature.byteLength !== 64) {
      unavailable();
    }
    await assertPending(initial, pending);
    check(initial);
    const valid = await cryptoImpl.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signature,
      message
    );
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    if (valid !== true) unavailable();
    return record;
  };
  const validateDurableRelationship = async (record) => {
    if (typeof cryptoImpl?.subtle?.importKey !== "function" ||
        typeof cryptoImpl.subtle.sign !== "function" ||
        typeof cryptoImpl.subtle.verify !== "function") unavailable();
    const publicKey = await cryptoImpl.subtle.importKey(
      "raw",
      fromHex(record.ed25519PublicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    publicVerificationKey(publicKey, CryptoKeyImpl);
    const message = encoder.encode(canonical({
      deviceId: record.deviceId,
      domain: KEY_RELATION_DOMAIN,
      publicKey: record.ed25519PublicKey,
      recordRevision: record.recordRevision,
      requestId: record.requestId,
      subject: record.subjectHint,
      version: 2
    }));
    const signature = await cryptoImpl.subtle.sign(
      { name: "Ed25519" },
      record.privateKey,
      message
    );
    if (!(signature instanceof ArrayBuffer) || signature.byteLength !== 64) {
      unavailable();
    }
    if (await cryptoImpl.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signature,
      message
    ) !== true) unavailable();
    return record;
  };
  const expectedRecord = async (initial, pending, content, publicKey, privateKey) => {
    check(initial);
    const semantic = await inspectMessagingDeviceAuthorizationClaim(content, {
      subject: initial.subjectHint,
      proposal: pending.proposal,
      cryptoImpl
    });
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    if (
      semantic.action !== "register" || semantic.binding.operation !== "register" ||
      semantic.binding.bindingVersion !== 1 ||
      semantic.binding.deviceId !== pending.deviceId ||
      semantic.binding.publicKey !== pending.publicKey ||
      semantic.requestId !== pending.requestId
    ) unavailable();
    const bindingAuthorizationDigest = await cryptoImpl.subtle.digest(
      "SHA-256",
      encoder.encode(content)
    );
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    if (!(bindingAuthorizationDigest instanceof ArrayBuffer) ||
        bindingAuthorizationDigest.byteLength !== 32) unavailable();
    const x25519PublicKeyCommitment =
      "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
      await sha256Hex(cryptoImpl, X25519_COMMITMENT_DOMAIN, pending.publicKey);
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    return {
      schema: LOCAL_SCHEMA,
      version: 2,
      state: "prepared-provisional",
      subjectHint: initial.subjectHint,
      deviceId: pending.deviceId,
      requestId: pending.requestId,
      pendingProposal: pending.pendingProposal,
      x25519PublicKey: pending.publicKey,
      x25519BindingId: semantic.bindingId,
      x25519BindingVersion: 1,
      x25519PublicKeyCommitment,
      bindingAuthorizationContent: content,
      bindingAuthorizationDigest: toHex(bindingAuthorizationDigest),
      ed25519PublicKey: publicKey,
      recordRevision: toHex(cryptoImpl.getRandomValues(new Uint8Array(32))),
      privateKey,
      signingClaim: null,
      signedAttempt: null
    };
  };
  const matchesExpected = (record, expected) => {
    const fields = [
      "bindingAuthorizationContent", "bindingAuthorizationDigest", "deviceId",
      "pendingProposal", "requestId", "subjectHint", "x25519BindingId",
      "x25519BindingVersion", "x25519PublicKey", "x25519PublicKeyCommitment"
    ];
    if (fields.some((field) => record[field] !== expected[field])) unavailable();
    return record;
  };
  const prepare = async (bindingAuthorizationContent) => {
    try {
      if (typeof bindingAuthorizationContent !== "string") unavailable();
      const initial = currentContext(getContext);
      const pending = await readPending(initial);
      check(initial);
      const template = await expectedRecord(
        initial,
        pending,
        bindingAuthorizationContent,
        "00".repeat(32),
        null
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      const existing = await readStored(initial, pending.deviceId);
      check(initial);
      if (existing !== undefined) {
        matchesExpected(existing, template);
        await validateRelationship(existing, initial, pending);
        check(initial);
        await assertPending(initial, pending);
        check(initial);
        return publicRecord(existing);
      }
      if (
        typeof cryptoImpl?.subtle?.generateKey !== "function" ||
        typeof cryptoImpl.subtle.exportKey !== "function" ||
        typeof cryptoImpl.getRandomValues !== "function"
      ) unavailable();
      const pair = await cryptoImpl.subtle.generateKey(
        { name: "Ed25519" },
        false,
        ["sign", "verify"]
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      privateSigningKey(pair?.privateKey, CryptoKeyImpl);
      if (
        !(pair?.publicKey instanceof CryptoKeyImpl) ||
        pair.publicKey.type !== "public" || pair.publicKey.extractable !== true ||
        pair.publicKey.algorithm?.name !== "Ed25519" ||
        pair.publicKey.usages.length !== 1 || pair.publicKey.usages[0] !== "verify"
      ) unavailable();
      const raw = await cryptoImpl.subtle.exportKey("raw", pair.publicKey);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (!(raw instanceof ArrayBuffer) || raw.byteLength !== 32) unavailable();
      const record = await expectedRecord(
        initial,
        pending,
        bindingAuthorizationContent,
        toHex(raw),
        pair.privateKey
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      localRecord(record, initial.subjectHint, CryptoKeyImpl);
      await validateRelationship(record, initial, pending);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      try {
        await store.create(
          pending,
          record,
          initial.subjectHint,
          CryptoKeyImpl,
          () => check(initial)
        );
      } catch {
        check(initial);
        await assertPending(initial, pending);
        check(initial);
        const winner = await readStored(initial, pending.deviceId);
        check(initial);
        if (winner === undefined) unavailable();
        matchesExpected(winner, record);
        await validateRelationship(winner, initial, pending);
        check(initial);
        await assertPending(initial, pending);
        check(initial);
        return publicRecord(winner);
      }
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      const stored = await readStored(initial, pending.deviceId);
      check(initial);
      if (stored === undefined || !sameIdentity(stored, record)) unavailable();
      await validateRelationship(stored, initial, pending);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      return publicRecord(stored);
    } catch {
      unavailable();
    }
  };
  const loadBound = async (initial) => {
    const pending = await readPending(initial);
    check(initial);
    const record = await readStored(initial, pending.deviceId);
    check(initial);
    if (record === undefined) unavailable();
    const template = await expectedRecord(
      initial,
      pending,
      record.bindingAuthorizationContent,
      record.ed25519PublicKey,
      record.privateKey
    );
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    matchesExpected(record, template);
    await validateRelationship(record, initial, pending);
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    return Object.freeze({ pending, record });
  };
  const claimWire = async (authorizationWire, record, pending, initial) => {
    const envelope = await parseAuthorizationEnvelopeV2(authorizationWire, {
      subject: record.subjectHint,
      proposal: pending.proposal,
      cryptoImpl
    });
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    if (
      envelope.preEnrollment.deviceId !== record.deviceId ||
      envelope.preEnrollment.requestId !== record.requestId ||
      envelope.preEnrollment.x25519BindingId !== record.x25519BindingId ||
      envelope.preEnrollment.x25519BindingVersion !== record.x25519BindingVersion ||
      envelope.preEnrollment.x25519PublicKeyCommitment !==
        record.x25519PublicKeyCommitment ||
      envelope.preEnrollment.ed25519PublicKey !== record.ed25519PublicKey ||
      envelope.preEnrollment.bindingAuthorizationDigest !==
        record.bindingAuthorizationDigest ||
      envelope.content !== record.bindingAuthorizationContent
    ) unavailable();
    const authorizationDigest = await authorizationDigestV2(authorizationWire, {
      subject: record.subjectHint,
      proposal: pending.proposal,
      cryptoImpl
    });
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    const preEnrollmentDigest = await preEnrollmentDigestV2(
      envelope.preEnrollment.wire,
      cryptoImpl
    );
    check(initial);
    await assertPending(initial, pending);
    check(initial);
    return canonical({
      authorizationDigest,
      authorizationWire,
      deviceId: record.deviceId,
      ed25519PublicKey: record.ed25519PublicKey,
      pairingId: envelope.preEnrollment.pairingId,
      preEnrollmentDigest,
      recordRevision: record.recordRevision,
      requestId: record.requestId,
      schema: SIGNING_CLAIM_SCHEMA,
      state: "signing-claimed",
      subject: record.subjectHint,
      version: 2,
      x25519BindingId: record.x25519BindingId,
      x25519BindingVersion: record.x25519BindingVersion,
      x25519PublicKeyCommitment: record.x25519PublicKeyCommitment
    });
  };
  const durablePending = (record) => {
    const pendingProposal = canonicalMessagingDeviceAuthorizationProposal({
      deviceId: record.deviceId,
      expectedBindingId: null,
      operation: "register",
      publicKey: record.x25519PublicKey,
      requestId: record.requestId
    });
    if (record.pendingProposal !== pendingProposal) unavailable();
    return Object.freeze({
      deviceId: record.deviceId,
      pendingProposal,
      proposal: Object.freeze(JSON.parse(pendingProposal)),
      publicKey: record.x25519PublicKey,
      requestId: record.requestId,
      subjectHint: record.subjectHint
    });
  };
  const authenticateDurableClaim = async (claim, signingClaimWire, record) => {
    if (
      record.signingClaim !== signingClaimWire ||
      claim.recordRevision !== record.recordRevision ||
      claim.subject !== record.subjectHint || claim.deviceId !== record.deviceId ||
      claim.requestId !== record.requestId ||
      claim.ed25519PublicKey !== record.ed25519PublicKey ||
      claim.x25519BindingId !== record.x25519BindingId ||
      claim.x25519BindingVersion !== record.x25519BindingVersion ||
      claim.x25519PublicKeyCommitment !== record.x25519PublicKeyCommitment
    ) unavailable();
    const pending = durablePending(record);
    const options = {
      subject: record.subjectHint,
      proposal: pending.proposal,
      cryptoImpl
    };
    const envelope = await parseAuthorizationEnvelopeV2(
      claim.authorizationWire,
      options
    );
    if (
      envelope.content !== record.bindingAuthorizationContent ||
      envelope.preEnrollment.bindingAuthorizationDigest !==
        record.bindingAuthorizationDigest ||
      envelope.preEnrollment.deviceId !== record.deviceId ||
      envelope.preEnrollment.requestId !== record.requestId ||
      envelope.preEnrollment.ed25519PublicKey !== record.ed25519PublicKey ||
      envelope.preEnrollment.x25519BindingId !== record.x25519BindingId ||
      envelope.preEnrollment.x25519BindingVersion !==
        record.x25519BindingVersion ||
      envelope.preEnrollment.x25519PublicKeyCommitment !==
        record.x25519PublicKeyCommitment
    ) unavailable();
    const authorizationDigest = await authorizationDigestV2(
      claim.authorizationWire,
      options
    );
    const preEnrollmentDigest = await preEnrollmentDigestV2(
      envelope.preEnrollment.wire,
      cryptoImpl
    );
    const expectedClaimWire = canonical({
      authorizationDigest,
      authorizationWire: claim.authorizationWire,
      deviceId: record.deviceId,
      ed25519PublicKey: record.ed25519PublicKey,
      pairingId: envelope.preEnrollment.pairingId,
      preEnrollmentDigest,
      recordRevision: record.recordRevision,
      requestId: record.requestId,
      schema: SIGNING_CLAIM_SCHEMA,
      state: "signing-claimed",
      subject: record.subjectHint,
      version: 2,
      x25519BindingId: record.x25519BindingId,
      x25519BindingVersion: record.x25519BindingVersion,
      x25519PublicKeyCommitment: record.x25519PublicKeyCommitment
    });
    if (
      expectedClaimWire !== signingClaimWire ||
      claim.authorizationDigest !== authorizationDigest ||
      claim.preEnrollmentDigest !== preEnrollmentDigest ||
      claim.pairingId !== envelope.preEnrollment.pairingId
    ) unavailable();
    await validateDurableRelationship(record);
    return Object.freeze({ envelope, options, pending });
  };
  const claimSigningAttempt = async (authorizationWire) => {
    try {
      const initial = currentContext(getContext);
      const { pending, record } = await loadBound(initial);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      const expected = await claimWire(
        authorizationWire,
        record,
        pending,
        initial
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      parseSigningClaim(expected);
      check(initial);
      await assertPending(initial, pending);
      const outcome = await store.claim(
        pending,
        record,
        expected,
        initial.subjectHint,
        CryptoKeyImpl,
        () => check(initial)
      );
      check(initial);
      await assertPending(initial, pending);
      const after = await readStored(initial, record.deviceId);
      check(initial);
      if (after === undefined || !sameIdentity(after, record)) unavailable();
      await validateRelationship(after, initial, pending);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (outcome.kind === "existing-claim") {
        if (outcome.wire !== expected) unavailable();
        return Object.freeze({ status: "ambiguous", signingClaimWire: expected });
      }
      if (outcome.kind === "signed") {
        const parsed = await parseSignedAttemptV2(outcome.wire, {
          subject: record.subjectHint,
          proposal: pending.proposal,
          cryptoImpl
        });
        check(initial);
        await assertPending(initial, pending);
        check(initial);
        if (parsed.approval.envelope.wire !== authorizationWire) unavailable();
        return Object.freeze({ status: "signed", signedAttemptWire: outcome.wire });
      }
      if (outcome.kind !== "claimed" || outcome.wire !== expected) unavailable();
      return Object.freeze({ status: "claimed", signingClaimWire: expected });
    } catch {
      unavailable();
    }
  };
  const persistSignedAttempt = async (signingClaimWire, signedAttemptWire) => {
    try {
      const claim = parseSigningClaim(signingClaimWire);
      const raw = await store.read(claim.deviceId);
      if (raw === undefined) unavailable();
      const record = localRecord(raw, claim.subject, CryptoKeyImpl);
      const durable = await authenticateDurableClaim(
        claim,
        signingClaimWire,
        record
      );
      const attempt = await parseSignedAttemptV2(signedAttemptWire, {
        subject: record.subjectHint,
        proposal: durable.pending.proposal,
        cryptoImpl
      });
      if (attempt.approval.envelope.wire !== claim.authorizationWire) unavailable();
      const persisted = await store.persist(
        record.deviceId,
        record.recordRevision,
        signingClaimWire,
        signedAttemptWire,
        record,
        claim.subject,
        CryptoKeyImpl
      );
      if (persisted !== signedAttemptWire) unavailable();
      const afterRaw = await store.read(claim.deviceId);
      if (afterRaw === undefined) unavailable();
      const after = localRecord(afterRaw, claim.subject, CryptoKeyImpl);
      if (
        !sameIdentity(after, record) ||
        after.signingClaim !== signingClaimWire ||
        after.signedAttempt !== signedAttemptWire
      ) unavailable();
      await authenticateDurableClaim(claim, signingClaimWire, after);
      const afterAttempt = await parseSignedAttemptV2(after.signedAttempt, {
        subject: after.subjectHint,
        proposal: durable.pending.proposal,
        cryptoImpl
      });
      if (afterAttempt.approval.envelope.wire !== claim.authorizationWire) {
        unavailable();
      }
      return signedAttemptWire;
    } catch {
      unavailable();
    }
  };
  const readSignedAttempt = async (authorizationWire) => {
    try {
      const initial = currentContext(getContext);
      const { pending, record } = await loadBound(initial);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      const expectedClaim = await claimWire(
        authorizationWire,
        record,
        pending,
        initial
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (record.signedAttempt === null) return undefined;
      if (record.signingClaim !== expectedClaim) unavailable();
      const parsed = await parseSignedAttemptV2(record.signedAttempt, {
        subject: record.subjectHint,
        proposal: pending.proposal,
        cryptoImpl
      });
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (parsed.approval.envelope.wire !== authorizationWire) unavailable();
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      return record.signedAttempt;
    } catch {
      unavailable();
    }
  };
  const createEnrollmentProofV2 = async (enrollmentWire) => {
    try {
      const initial = currentContext(getContext);
      const enrollment = parseEnrollment(enrollmentWire);
      const currentNow = now();
      if (
        enrollment.subject !== initial.subjectHint ||
        !Number.isSafeInteger(currentNow) || currentNow < enrollment.issuedAt ||
        currentNow >= enrollment.expiresAt
      ) unavailable();
      const { pending, record } = await loadBound(initial);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (
        enrollment.deviceId !== record.deviceId ||
        enrollment.x25519BindingId !== record.x25519BindingId ||
        enrollment.x25519BindingVersion !== record.x25519BindingVersion ||
        enrollment.x25519PublicKeyCommitment !==
          record.x25519PublicKeyCommitment ||
        enrollment.ed25519PublicKey !== record.ed25519PublicKey
      ) unavailable();
      const enrollmentDigest =
        "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
        await sha256Hex(cryptoImpl, ENROLLMENT_DIGEST_DOMAIN, enrollmentWire);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      const preimage = canonical({
        domain: ENROLLMENT_PROOF_DOMAIN,
        enrollment: enrollmentWire,
        profile: PROFILE,
        publicKey: record.ed25519PublicKey,
        schema: ENROLLMENT_PROOF_PREIMAGE_SCHEMA,
        version: 2
      });
      const signature = await cryptoImpl.subtle.sign(
        { name: "Ed25519" },
        record.privateKey,
        encoder.encode(preimage)
      );
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (!(signature instanceof ArrayBuffer) || signature.byteLength !== 64) {
        unavailable();
      }
      const after = await loadBound(initial);
      check(initial);
      await assertPending(initial, pending);
      check(initial);
      if (!sameIdentity(record, after.record)) unavailable();
      const finishedAt = now();
      if (
        !Number.isSafeInteger(finishedAt) || finishedAt < enrollment.issuedAt ||
        finishedAt >= enrollment.expiresAt
      ) unavailable();
      const proof = canonical({
        algorithm: "Ed25519",
        enrollmentChallengeId: enrollment.enrollmentChallengeId,
        enrollmentDigest,
        profile: PROFILE,
        publicKey: record.ed25519PublicKey,
        schema: ENROLLMENT_PROOF_SCHEMA,
        signature: toHex(signature),
        version: 2
      });
      const parsed = JSON.parse(proof);
      if (canonical(parsed) !== proof || !HEX128.test(parsed.signature)) unavailable();
      return proof;
    } catch {
      unavailable();
    }
  };
  return Object.freeze({
    claimSigningAttempt,
    createEnrollmentProofV2,
    persistSignedAttempt,
    prepare,
    readSignedAttempt
  });
}
