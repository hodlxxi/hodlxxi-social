import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createMessagingDeviceEd25519KeyV2 } from
  "../web/messaging-device-ed25519-key-v2.mjs";
import { createMessagingDeviceStore } from
  "../web/messaging-device-v128c1.mjs";
import {
  approvalEventIdV2,
  approvalUnsignedEventV2,
  authorizationDigestV2,
  createAuthorizationEnvelopeV2,
  createPreEnrollmentV2,
  createSignedAttemptV2
} from "../web/mobile-device-authorization-contract-v2.mjs";
import {
  createDesktopPreEnrollmentApprovalV2,
  preEnrollmentComparisonCode
} from "../web/mobile-device-authorization-seams-v2.mjs";

const NativeCryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
const vector = JSON.parse(await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
  import.meta.url
))).vector;
const fixturePre = JSON.parse(vector.preEnrollmentWire);
const fixtureOuter = JSON.parse(vector.authorizationWire);
const subject = fixturePre.subject;
const revision = "aa".repeat(32);
const x25519PublicKey = "09" + "00".repeat(31);
const proposal = Object.freeze({
  deviceId: fixturePre.deviceId,
  expectedBindingId: null,
  operation: "register",
  publicKey: x25519PublicKey,
  requestId: fixturePre.requestId
});
const pendingProposal = JSON.stringify({
  deviceId: proposal.deviceId,
  expectedBindingId: null,
  operation: "register",
  publicKey: proposal.publicKey,
  requestId: proposal.requestId
});
const x25519Pair = await webcrypto.subtle.generateKey(
  { name: "X25519" },
  false,
  ["deriveBits"]
);
const unavailable = {
  name: "Error",
  message: "messaging device provisional authentication key unavailable"
};
const seamUnavailable = {
  name: "TypeError",
  message: "mobile device authorization v2 seam unavailable"
};

const FIELD_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GENERATOR = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
const mod = (value, modulus = FIELD_P) =>
  (value % modulus + modulus) % modulus;
const pow = (base, exponent) => {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
};
const add = (left, right) => {
  if (!left) return right;
  if (!right) return left;
  if (left.x === right.x && left.y !== right.y) return null;
  const slope = left.x === right.x
    ? mod(3n * left.x * left.x * pow(2n * left.y, FIELD_P - 2n))
    : mod((right.y - left.y) * pow(right.x - left.x, FIELD_P - 2n));
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
};
const multiply = (scalar) => {
  let result = null;
  let addend = GENERATOR;
  let value = scalar;
  while (value > 0n) {
    if (value & 1n) result = add(result, addend);
    addend = add(addend, addend);
    value >>= 1n;
  }
  return result;
};
const scalarBytes = (value) => Buffer.from(
  value.toString(16).padStart(64, "0"),
  "hex"
);
const taggedHash = (tag, ...parts) => {
  const tagHash = createHash("sha256").update(tag).digest();
  return createHash("sha256")
    .update(tagHash).update(tagHash).update(Buffer.concat(parts)).digest();
};
const signNostrId = (id) => {
  const secret = 3n;
  const publicPoint = multiply(secret);
  const privateScalar = publicPoint.y & 1n ? CURVE_N - secret : secret;
  const auxiliary = taggedHash("BIP0340/aux", Buffer.alloc(32));
  const masked = Buffer.from(scalarBytes(privateScalar).map(
    (byte, index) => byte ^ auxiliary[index]
  ));
  const nonceCandidate = BigInt("0x" + taggedHash(
    "BIP0340/nonce",
    masked,
    scalarBytes(publicPoint.x),
    Buffer.from(id, "hex")
  ).toString("hex")) % CURVE_N;
  const noncePoint = multiply(nonceCandidate);
  const nonce = noncePoint.y & 1n
    ? CURVE_N - nonceCandidate : nonceCandidate;
  const challenge = BigInt("0x" + taggedHash(
    "BIP0340/challenge",
    scalarBytes(noncePoint.x),
    scalarBytes(publicPoint.x),
    Buffer.from(id, "hex")
  ).toString("hex")) % CURVE_N;
  return Buffer.concat([
    scalarBytes(noncePoint.x),
    scalarBytes(mod(nonce + challenge * privateScalar, CURVE_N))
  ]).toString("hex");
};

function pending(changes = {}) {
  return {
    deviceId: proposal.deviceId,
    pendingProposal,
    publicKey: proposal.publicKey,
    requestId: proposal.requestId,
    state: "pending-register",
    subject,
    ...changes
  };
}

function pendingLocal(changes = {}) {
  return {
    acceptedBinding: null,
    authorization: null,
    deviceId: proposal.deviceId,
    pendingAuthorization: null,
    pendingProposal,
    privateKey: x25519Pair.privateKey,
    publicKey: proposal.publicKey,
    requestId: proposal.requestId,
    rotation: null,
    schema: "hodlxxi.social_messaging_device_local.v1",
    state: "pending-register",
    subject,
    version: 1,
    ...changes
  };
}

function pendingFromDevice(record) {
  return {
    deviceId: record.deviceId,
    pendingProposal: record.pendingProposal,
    publicKey: record.publicKey,
    requestId: record.requestId,
    state: record.state,
    subject: record.subject
  };
}

function idbHarness({
  beforeAtomic,
  beforePut,
  blocked = false,
  deviceRecord = pendingLocal(),
  durability = "strict",
  holdAtomic,
  metadata = {},
  topology = ["device"],
  version = 1
} = {}) {
  let databaseVersion = version;
  const databaseStores = new Map(
    topology.map((name) => [name, new Map()])
  );
  const storeMetadata = new Map(topology.map((name) => [name, {
    autoIncrement: false,
    indexNames: [],
    keyPath: null,
    ...metadata[name]
  }]));
  if (deviceRecord !== undefined && databaseStores.has("device")) {
    databaseStores.get("device").set("current", structuredClone(deviceRecord));
  }
  const transactionQueue = [];
  let active;
  const names = [];
  const upgradeStores = [];
  let heldAtomic = false;
  let atomicCount = 0;
  let blockedContinuation;
  const metadataView = (storeName) => {
    if (!storeMetadata.has(storeName)) throw new Error("NotFoundError");
    const value = storeMetadata.get(storeName);
    return {
      autoIncrement: value.autoIncrement,
      indexNames: [...value.indexNames],
      keyPath: value.keyPath
    };
  };
  const pump = () => {
    if (active || transactionQueue.length === 0) return;
    active = transactionQueue.shift();
    if (active.mode === "readwrite" && active.storeNames.length === 2) {
      atomicCount += 1;
      beforeAtomic?.({
        count: atomicCount,
        read(storeName, key) {
          const value = databaseStores.get(storeName)?.get(key);
          return value === undefined ? undefined : structuredClone(value);
        },
        write(storeName, key, value) {
          databaseStores.get(storeName)?.set(key, structuredClone(value));
        }
      });
    }
    active.views = new Map(active.storeNames.map((name) => [
      name,
      new Map(Array.from(databaseStores.get(name), ([key, value]) => [
        key,
        structuredClone(value)
      ]))
    ]));
    const step = () => queueMicrotask(() => {
      const tx = active;
      if (!tx || tx.aborted) {
        active = undefined;
        pump();
        return;
      }
      const operation = tx.operations.shift();
      if (operation === undefined) {
        if (tx.mode === "readwrite") {
          for (const [name, values] of tx.views) {
            databaseStores.set(name, values);
          }
        }
        tx.oncomplete?.();
        active = undefined;
        pump();
        return;
      }
      const { kind, key, request, storeName, value } = operation;
      const values = tx.views.get(storeName);
      if (kind === "get") {
        request.result = values.has(key)
          ? structuredClone(values.get(key)) : undefined;
        request.onsuccess?.();
      } else if (kind === "add" && values.has(key)) {
        tx.abort();
        return;
      } else {
        values.set(key, structuredClone(value));
        request.result = key;
        request.onsuccess?.();
      }
      step();
    });
    if (
      holdAtomic && !heldAtomic &&
      atomicCount === (holdAtomic.when ?? 1)
    ) {
      heldAtomic = true;
      holdAtomic.entered();
      holdAtomic.gate.then(step);
    } else {
      step();
    }
  };
  const schedule = (tx, operation) => {
    const request = {};
    tx.operations.push({ ...operation, request });
    if (!tx.scheduled) {
      tx.scheduled = true;
      transactionQueue.push(tx);
      pump();
    }
    return request;
  };
  const factory = {
    open(name, requestedVersion) {
      names.push([name, requestedVersion]);
      let upgradeAborted = false;
      const db = {
        get version() { return databaseVersion; },
        get objectStoreNames() {
          return Array.from(databaseStores.keys()).sort();
        },
        close() {},
        createObjectStore(nameValue) {
          if (databaseStores.has(nameValue)) throw new Error("ConstraintError");
          databaseStores.set(nameValue, new Map());
          storeMetadata.set(nameValue, {
            autoIncrement: false,
            indexNames: [],
            keyPath: null
          });
          upgradeStores.push(nameValue);
          return metadataView(nameValue);
        },
        transaction(storeNames, mode, options) {
          const selected = (Array.isArray(storeNames) ? storeNames : [storeNames]);
          for (const storeName of selected) {
            if (!databaseStores.has(storeName)) throw new Error("NotFoundError");
          }
          if (mode === "readwrite") {
            assert.deepEqual(options, { durability: "strict" });
          } else {
            assert.equal(mode, "readonly");
            assert.equal(options, undefined);
          }
          const tx = {
            aborted: false,
            durability,
            mode,
            operations: [],
            scheduled: false,
            storeNames: [...selected],
            abort() {
              if (tx.aborted) return;
              tx.aborted = true;
              queueMicrotask(() => tx.onabort?.());
              if (active === tx) {
                active = undefined;
                pump();
              }
            },
            objectStore(storeName) {
              assert.equal(selected.includes(storeName), true);
              return {
                ...metadataView(storeName),
                get: (key) => schedule(tx, { kind: "get", key, storeName }),
                add: (value, key) => schedule(tx, {
                  kind: "add", key, storeName, value
                }),
                put: (value, key) => {
                  beforePut?.({ key, storeName, value });
                  return schedule(tx, { kind: "put", key, storeName, value });
                }
              };
            }
          };
          return tx;
        }
      };
      const request = { result: db };
      const continueOpen = () => {
        if (blocked) {
          blockedContinuation = undefined;
        }
        const targetVersion = requestedVersion ?? (databaseVersion || 1);
        if (targetVersion < databaseVersion) {
          request.error = Object.assign(new Error("VersionError"), {
            name: "VersionError"
          });
          request.onerror?.();
          return;
        }
        if (targetVersion > databaseVersion || databaseVersion === 0) {
          const oldVersion = databaseVersion;
          const oldStores = new Map(databaseStores);
          const oldMetadata = new Map(storeMetadata);
          databaseVersion = targetVersion;
          request.transaction = {
            abort() { upgradeAborted = true; },
            objectStore: metadataView
          };
          request.onupgradeneeded?.({ oldVersion, newVersion: targetVersion });
          if (upgradeAborted) {
            databaseVersion = oldVersion;
            databaseStores.clear();
            for (const [storeName, values] of oldStores) {
              databaseStores.set(storeName, values);
            }
            storeMetadata.clear();
            for (const [storeName, value] of oldMetadata) {
              storeMetadata.set(storeName, value);
            }
            request.onerror?.();
            return;
          }
        }
        request.onsuccess?.();
      };
      queueMicrotask(() => {
        if (blocked) {
          request.onblocked?.();
          blockedContinuation = continueOpen;
          return;
        }
        continueOpen();
      });
      return request;
    }
  };
  return {
    factory,
    names,
    upgradeStores,
    releaseBlocker() {
      if (typeof blockedContinuation !== "function") {
        throw new Error("no blocked open request");
      }
      const continuation = blockedContinuation;
      blockedContinuation = undefined;
      continuation();
    },
    device: () => databaseStores.get("device")?.has("current")
      ? structuredClone(databaseStores.get("device").get("current"))
      : undefined,
    replaceDevice(value) {
      databaseStores.get("device")?.set("current", structuredClone(value));
    },
    stored: (key = proposal.deviceId) =>
      databaseStores.get("provisional-authentication-key-v2")?.has(key)
        ? structuredClone(
            databaseStores.get("provisional-authentication-key-v2").get(key)
          )
        : undefined,
    replace(key, value) {
      databaseStores.get("provisional-authentication-key-v2")
        ?.set(key, structuredClone(value));
    },
    topology: () => Array.from(databaseStores.keys()).sort(),
    version: () => databaseVersion,
    writeDevice(value) {
      return new Promise((resolve, reject) => {
        const db = factory.open("hodlxxi-social-messaging-device-v1").result;
        const tx = db.transaction("device", "readwrite", {
          durability: "strict"
        });
        tx.oncomplete = resolve;
        tx.onabort = tx.onerror = reject;
        tx.objectStore("device").put(value, "current");
      });
    }
  };
}

function setup({
  idb = idbHarness(),
  contextState = { subjectHint: subject, revision },
  getContext,
  cryptoImpl = webcrypto,
  now = () => fixturePre.issuedAt + 1_000
} = {}) {
  const boundary = createMessagingDeviceEd25519KeyV2({
    getContext: getContext ?? (() => ({ ...contextState })),
    indexedDBImpl: idb.factory,
    cryptoImpl,
    CryptoKeyImpl: NativeCryptoKey,
    now
  });
  return { boundary, contextState, idb };
}

async function outerFor(prepared) {
  const preWire = createPreEnrollmentV2({
    bindingAuthorizationDigest: fixturePre.bindingAuthorizationDigest,
    deviceId: prepared.deviceId,
    ed25519PublicKey: prepared.ed25519PublicKey,
    expiresAt: fixturePre.expiresAt,
    issuedAt: fixturePre.issuedAt,
    pairingId: fixturePre.pairingId,
    requestId: prepared.requestId,
    subject: prepared.subjectHint,
    x25519BindingId: prepared.x25519BindingId,
    x25519BindingVersion: prepared.x25519BindingVersion,
    x25519PublicKeyCommitment: prepared.x25519PublicKeyCommitment
  });
  return createAuthorizationEnvelopeV2({
    content: fixtureOuter.content,
    contextWire: JSON.stringify(fixtureOuter.context,
      Object.keys(fixtureOuter.context).sort()),
    preEnrollmentWire: preWire
  }, { subject, proposal, cryptoImpl: webcrypto });
}

async function signedEventFor(authorizationWire) {
  const options = { subject, proposal, cryptoImpl: webcrypto };
  const unsigned = await approvalUnsignedEventV2(authorizationWire, options);
  const id = await approvalEventIdV2(authorizationWire, options);
  return Object.freeze({
    ...unsigned,
    id,
    pubkey: subject,
    sig: signNostrId(id)
  });
}

const changedWire = (source, changes) => {
  const value = { ...JSON.parse(source), ...changes };
  return JSON.stringify(value, Object.keys(value).sort());
};

function countingCrypto() {
  let signCalls = 0;
  const subtle = Object.freeze({
    digest: (...args) => webcrypto.subtle.digest(...args),
    exportKey: (...args) => webcrypto.subtle.exportKey(...args),
    generateKey: (...args) => webcrypto.subtle.generateKey(...args),
    importKey: (...args) => webcrypto.subtle.importKey(...args),
    sign: (...args) => {
      signCalls += 1;
      return webcrypto.subtle.sign(...args);
    },
    verify: (...args) => webcrypto.subtle.verify(...args)
  });
  return Object.freeze({
    getRandomValues: (...args) => webcrypto.getRandomValues(...args),
    signCalls: () => signCalls,
    subtle
  });
}

test("version-1 upgrade preserves X25519 record/key and exact opener topology", async () => {
  const idb = idbHarness();
  const xStore = createMessagingDeviceStore(idb.factory);
  const before = await xStore.read();
  assert.equal(idb.version(), 1);
  assert.deepEqual(idb.topology(), ["device"]);
  assert.equal(before.privateKey.extractable, false);
  assert.equal(before.privateKey.algorithm.name, "X25519");

  const v2 = setup({ idb });
  await assert.rejects(
    v2.boundary.readSignedAttempt(vector.authorizationWire),
    unavailable
  );
  assert.equal(idb.version(), 2);
  assert.deepEqual(idb.topology(), [
    "device", "provisional-authentication-key-v2"
  ]);
  assert.equal(idb.stored(), undefined);
  const afterUpgrade = await xStore.read();
  assert.deepEqual(
    { ...afterUpgrade, privateKey: null },
    { ...before, privateKey: null }
  );
  const peer = await webcrypto.subtle.generateKey(
    { name: "X25519" }, false, ["deriveBits"]
  );
  const beforeBits = await webcrypto.subtle.deriveBits(
    { name: "X25519", public: peer.publicKey },
    before.privateKey,
    256
  );
  const afterBits = await webcrypto.subtle.deriveBits(
    { name: "X25519", public: peer.publicKey },
    afterUpgrade.privateKey,
    256
  );
  assert.deepEqual(new Uint8Array(afterBits), new Uint8Array(beforeBits));

  await xStore.update({
    ...afterUpgrade,
    pendingProposal: null,
    state: "revoked"
  }, afterUpgrade);
  const updated = await xStore.read();
  assert.equal(updated.state, "revoked");
  assert.equal(updated.privateKey.extractable, false);
  assert.deepEqual(
    new Uint8Array(await webcrypto.subtle.deriveBits(
      { name: "X25519", public: peer.publicKey },
      updated.privateKey,
      256
    )),
    new Uint8Array(beforeBits)
  );

  await assert.rejects(new Promise((resolve, reject) => {
    const request = idb.factory.open("hodlxxi-social-messaging-device-v1", 1);
    request.onsuccess = resolve;
    request.onerror = () => reject(request.error);
  }), { name: "VersionError" });
});

test("X-only and V2-owned fresh opens plus blocked/version/topology failures are exact", async () => {
  const existingX = idbHarness();
  assert.ok(await createMessagingDeviceStore(existingX.factory).read());
  assert.equal(existingX.version(), 1);
  assert.deepEqual(existingX.topology(), ["device"]);

  const freshX = idbHarness({
    deviceRecord: undefined,
    topology: [],
    version: 0
  });
  assert.equal(await createMessagingDeviceStore(freshX.factory).read(), undefined);
  assert.equal(freshX.version(), 1);
  assert.deepEqual(freshX.topology(), ["device"]);

  const freshV2 = idbHarness({
    deviceRecord: undefined,
    topology: [],
    version: 0
  });
  await assert.rejects(
    setup({ idb: freshV2 }).boundary.prepare(fixtureOuter.content),
    unavailable
  );
  assert.equal(freshV2.version(), 2);
  assert.deepEqual(freshV2.topology(), [
    "device", "provisional-authentication-key-v2"
  ]);

  for (const [name, idb] of [
    ["blocked", idbHarness({ blocked: true })],
    ["unknown-version", idbHarness({
      topology: ["device", "provisional-authentication-key-v2"],
      version: 3
    })],
    ["invalid-v1-topology", idbHarness({
      topology: ["wrong"],
      version: 1
    })],
    ["invalid-v2-topology", idbHarness({
      topology: ["device"],
      version: 2
    })]
  ]) {
    await assert.rejects(
      setup({ idb }).boundary.prepare(fixtureOuter.content),
      unavailable,
      name
    );
  }
  await assert.rejects(
    createMessagingDeviceStore(idbHarness({
      topology: ["device", "provisional-authentication-key-v2"],
      version: 3
    }).factory).read(),
    /device store unavailable/
  );
});

test("blocked V2 upgrade release aborts without schema or V1 record mutation", async () => {
  const idb = idbHarness({ blocked: true });
  const before = idb.device();
  await assert.rejects(
    setup({ idb }).boundary.readSignedAttempt(vector.authorizationWire),
    unavailable
  );
  assert.equal(idb.version(), 1);
  assert.deepEqual(idb.topology(), ["device"]);
  assert.deepEqual(idb.device(), before);

  idb.releaseBlocker();
  for (let step = 0; step < 5; step += 1) await Promise.resolve();
  assert.equal(idb.version(), 1);
  assert.deepEqual(idb.topology(), ["device"]);
  assert.deepEqual(idb.upgradeStores, []);
  assert.deepEqual(idb.device(), before);
});

const malformedStoreMetadata = [
  ["wrong keyPath", { keyPath: "id" }],
  ["autoIncrement true", { autoIncrement: true }],
  ["unexpected index", { indexNames: ["unexpected"] }]
];

test("malformed V1 metadata aborts V2 upgrade and rolls back exactly", async () => {
  for (const [name, malformed] of malformedStoreMetadata) {
    const idb = idbHarness({ metadata: { device: malformed } });
    const before = idb.device();
    await assert.rejects(
      setup({ idb }).boundary.readSignedAttempt(vector.authorizationWire),
      unavailable,
      name
    );
    assert.equal(idb.version(), 1, name);
    assert.deepEqual(idb.topology(), ["device"], name);
    assert.deepEqual(idb.upgradeStores, [], name);
    assert.deepEqual(idb.device(), before, name);
  }
});

test("every V1/V2 opener rejects non-exact metadata for every supported store", async () => {
  for (const [name, malformed] of malformedStoreMetadata) {
    const xV1 = idbHarness({ metadata: { device: malformed } });
    const xV1Before = xV1.device();
    await assert.rejects(
      createMessagingDeviceStore(xV1.factory).read(),
      /device store unavailable/,
      `X25519 V1 ${name}`
    );
    assert.deepEqual(xV1.device(), xV1Before, `X25519 V1 ${name}`);

    for (const malformedStore of [
      "device", "provisional-authentication-key-v2"
    ]) {
      const metadata = { [malformedStore]: malformed };
      const edV2 = idbHarness({
        metadata,
        topology: ["device", "provisional-authentication-key-v2"],
        version: 2
      });
      const edV2Before = edV2.device();
      await assert.rejects(
        setup({ idb: edV2 }).boundary.readSignedAttempt(
          vector.authorizationWire
        ),
        unavailable,
        `Ed25519 V2 ${malformedStore} ${name}`
      );
      assert.deepEqual(
        edV2.device(),
        edV2Before,
        `Ed25519 V2 ${malformedStore} ${name}`
      );

      const xV2 = idbHarness({
        metadata,
        topology: ["device", "provisional-authentication-key-v2"],
        version: 2
      });
      const xV2Before = xV2.device();
      await assert.rejects(
        createMessagingDeviceStore(xV2.factory).read(),
        /device store unavailable/,
        `X25519 V2 ${malformedStore} ${name}`
      );
      assert.deepEqual(
        xV2.device(),
        xV2Before,
        `X25519 V2 ${malformedStore} ${name}`
      );
    }
  }
});

test("the shared version-2 database persists one separate non-extractable sign-only key", async () => {
  const { boundary, idb } = setup();
  const prepared = await boundary.prepare(fixtureOuter.content);
  assert.equal(Object.isFrozen(prepared), true);
  assert.equal(prepared.state, "prepared-provisional");
  assert.equal(prepared.subjectHint, subject);
  assert.equal(prepared.deviceId, proposal.deviceId);
  assert.equal(prepared.requestId, proposal.requestId);
  assert.equal(prepared.x25519BindingId, fixturePre.x25519BindingId);
  assert.equal(prepared.x25519BindingVersion, 1);
  assert.equal(prepared.x25519PublicKeyCommitment,
    fixturePre.x25519PublicKeyCommitment);
  assert.match(prepared.ed25519PublicKey, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(prepared, "privateKey"), false);
  assert.deepEqual(new Set(idb.names.map(([name, version]) => `${name}:${version}`)),
    new Set(["hodlxxi-social-messaging-device-v1:2"]));
  assert.deepEqual(idb.upgradeStores, ["provisional-authentication-key-v2"]);
  assert.deepEqual(idb.topology(), [
    "device", "provisional-authentication-key-v2"
  ]);
  assert.equal(idb.version(), 2);
  const stored = idb.stored();
  assert.equal(stored.privateKey instanceof NativeCryptoKey, true);
  assert.equal(stored.privateKey.type, "private");
  assert.equal(stored.privateKey.extractable, false);
  assert.equal(stored.privateKey.algorithm.name, "Ed25519");
  assert.deepEqual(stored.privateKey.usages, ["sign"]);
  await assert.rejects(webcrypto.subtle.exportKey("pkcs8", stored.privateKey));
  await assert.rejects(webcrypto.subtle.exportKey("jwk", stored.privateKey));
});

test("concurrent tabs converge on the first writer and preserve stable key identity", async () => {
  const idb = idbHarness();
  const first = setup({ idb });
  const second = setup({ idb });
  const [left, right] = await Promise.all([
    first.boundary.prepare(fixtureOuter.content),
    second.boundary.prepare(fixtureOuter.content)
  ]);
  assert.deepEqual(left, right);
  const reopened = setup({ idb });
  assert.deepEqual(await reopened.boundary.prepare(fixtureOuter.content), left);
  assert.equal(idb.stored().ed25519PublicKey, left.ed25519PublicKey);
  assert.equal(idb.stored().recordRevision, left.recordRevision);
});

test("simultaneous mismatched create contenders preserve V1 and one exact winner", async () => {
  const mismatched = JSON.parse(fixtureOuter.content);
  mismatched.authorization.bindingExpiresAt = "2026-10-09T22:29:59Z";
  const mismatchedContent = JSON.stringify(mismatched);
  const idb = idbHarness();
  const before = idb.device();
  const contenders = await Promise.allSettled([
    setup({ idb }).boundary.prepare(fixtureOuter.content),
    setup({ idb }).boundary.prepare(mismatchedContent)
  ]);
  assert.deepEqual(contenders.map(({ status }) => status).sort(), [
    "fulfilled", "rejected"
  ]);
  const rejection = contenders.find(({ status }) => status === "rejected");
  assert.equal(rejection.reason?.name, unavailable.name);
  assert.equal(rejection.reason?.message, unavailable.message);
  assert.deepEqual(idb.device(), before);
  assert.equal([
    fixtureOuter.content,
    mismatchedContent
  ].includes(idb.stored().bindingAuthorizationContent), true);
});

test("stored private/public mismatch, wrong key properties and public binding corruption fail", async () => {
  const corruptions = [];
  const mismatch = await webcrypto.subtle.generateKey(
    { name: "Ed25519" }, false, ["sign", "verify"]
  );
  corruptions.push((record) => ({ ...record, privateKey: mismatch.privateKey }));
  const extractable = await webcrypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"]
  );
  corruptions.push((record) => ({ ...record, privateKey: extractable.privateKey }));
  const hmac = await webcrypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]
  );
  corruptions.push((record) => ({ ...record, privateKey: hmac }));
  corruptions.push((record) => ({ ...record, requestId: "ff".repeat(32) }));
  corruptions.push((record) => ({ ...record,
    x25519PublicKeyCommitment:
      "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
      "00".repeat(32)
  }));
  for (const corrupt of corruptions) {
    const instance = setup();
    await instance.boundary.prepare(fixtureOuter.content);
    instance.idb.replace(proposal.deviceId, corrupt(instance.idb.stored()));
    await assert.rejects(
      instance.boundary.prepare(fixtureOuter.content),
      unavailable
    );
  }
});

test("atomic create serializes both X25519 transition orders and the last context guard", async () => {
  const transitioned = pendingLocal({
    pendingProposal: null,
    state: "revoked"
  });

  const transitionFirst = setup();
  await transitionFirst.idb.writeDevice(transitioned);
  await assert.rejects(
    transitionFirst.boundary.prepare(fixtureOuter.content),
    unavailable
  );
  assert.equal(transitionFirst.idb.stored(), undefined);

  let enteredResolve;
  let release;
  const entered = new Promise((resolve) => { enteredResolve = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const idb = idbHarness({
    holdAtomic: { entered: enteredResolve, gate, when: 1 }
  });
  const v2First = setup({ idb });
  const create = v2First.boundary.prepare(fixtureOuter.content);
  await entered;
  const transition = idb.writeDevice(transitioned);
  release();
  await assert.rejects(create, unavailable);
  await transition;
  const durable = idb.stored();
  assert.match(durable.recordRevision, /^[0-9a-f]{64}$/);
  await assert.rejects(
    v2First.boundary.prepare(fixtureOuter.content),
    unavailable
  );
  assert.equal(idb.stored().recordRevision, durable.recordRevision);

  let contextEnteredResolve;
  let contextRelease;
  const contextEntered = new Promise((resolve) => {
    contextEnteredResolve = resolve;
  });
  const contextGate = new Promise((resolve) => { contextRelease = resolve; });
  const contextIdb = idbHarness({
    holdAtomic: {
      entered: contextEnteredResolve,
      gate: contextGate,
      when: 1
    }
  });
  const contextState = { subjectHint: subject, revision };
  const switched = setup({ idb: contextIdb, contextState });
  const work = switched.boundary.prepare(fixtureOuter.content);
  await contextEntered;
  contextState.revision = "bb".repeat(32);
  contextRelease();
  await assert.rejects(work, unavailable);
  assert.equal(contextIdb.stored(), undefined);
});

test("the same provisional key creates only the exact Enrollment V2 phone proof", async () => {
  const instance = setup();
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const source = JSON.parse(vector.enrollmentWire);
  const enrollmentWire = JSON.stringify({
    ...source,
    ed25519PublicKey: prepared.ed25519PublicKey
  }, Object.keys(source).sort());
  const proofWire = await instance.boundary.createEnrollmentProofV2(enrollmentWire);
  const proof = JSON.parse(proofWire);
  assert.equal(proof.publicKey, prepared.ed25519PublicKey);
  assert.match(proof.signature, /^[0-9a-f]{128}$/);
  const publicKey = await webcrypto.subtle.importKey(
    "raw",
    Buffer.from(proof.publicKey, "hex"),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const preimage = JSON.stringify({
    domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2",
    enrollment: enrollmentWire,
    profile: "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1",
    publicKey: prepared.ed25519PublicKey,
    schema: "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2",
    version: 2
  });
  assert.equal(await webcrypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    Buffer.from(proof.signature, "hex"),
    new TextEncoder().encode(preimage)
  ), true);
  await assert.rejects(instance.boundary.createEnrollmentProofV2(
    JSON.stringify({ ...source, ed25519PublicKey: "ff".repeat(32) },
      Object.keys(source).sort())
  ), unavailable);
});

test("Enrollment V2 uses the full frozen audience grammar before any Ed25519 sign", async () => {
  const audienceFixture = JSON.parse(await readFile(new URL(
    "./fixtures/social_messaging_device_proof_profile_v1.json",
    import.meta.url
  )));
  const cryptoImpl = countingCrypto();
  const instance = setup({ cryptoImpl });
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const source = JSON.parse(vector.enrollmentWire);
  const enrollmentWire = (audience) => JSON.stringify({
    ...source,
    audience,
    ed25519PublicKey: prepared.ed25519PublicKey
  }, Object.keys(source).sort());
  for (const { id, audience, accepted } of audienceFixture.audienceCorpus.cases) {
    const before = cryptoImpl.signCalls();
    const operation = instance.boundary.createEnrollmentProofV2(
      enrollmentWire(audience)
    );
    if (accepted) {
      assert.match(JSON.parse(await operation).signature, /^[0-9a-f]{128}$/, id);
    } else {
      await assert.rejects(operation, unavailable, id);
      assert.equal(cryptoImpl.signCalls(), before, id);
    }
  }
  for (const [id, audience] of [
    ["number", 1], ["null", null], ["object", {}], ["array", []]
  ]) {
    const before = cryptoImpl.signCalls();
    await assert.rejects(
      instance.boundary.createEnrollmentProofV2(enrollmentWire(audience)),
      unavailable,
      id
    );
    assert.equal(cryptoImpl.signCalls(), before, id);
  }
});

test("durable signer claim is CAS-bound and never reopens after ambiguity", async () => {
  const instance = setup();
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const authorizationWire = await outerFor(prepared);
  const claimed = await instance.boundary.claimSigningAttempt(authorizationWire);
  assert.equal(claimed.status, "claimed");
  assert.equal(typeof claimed.signingClaimWire, "string");
  const second = await instance.boundary.claimSigningAttempt(authorizationWire);
  assert.equal(second.status, "ambiguous");
  assert.equal(second.signingClaimWire, claimed.signingClaimWire);
  assert.equal(await instance.boundary.readSignedAttempt(authorizationWire),
    undefined);
  const stored = instance.idb.stored();
  instance.idb.replace(proposal.deviceId, {
    ...stored,
    recordRevision: "ff".repeat(32)
  });
  await assert.rejects(
    instance.boundary.claimSigningAttempt(authorizationWire),
    unavailable
  );
});

test("atomic claim serializes both X25519 transition orders and concurrent tabs", async () => {
  const transitioned = pendingLocal({
    pendingProposal: null,
    state: "revoked"
  });

  const transitionFirst = setup();
  const preparedFirst = await transitionFirst.boundary.prepare(
    fixtureOuter.content
  );
  const authorizationFirst = await outerFor(preparedFirst);
  await transitionFirst.idb.writeDevice(transitioned);
  await assert.rejects(
    transitionFirst.boundary.claimSigningAttempt(authorizationFirst),
    unavailable
  );
  assert.equal(transitionFirst.idb.stored().signingClaim, null);

  let enteredResolve;
  let release;
  const entered = new Promise((resolve) => { enteredResolve = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const idb = idbHarness({
    holdAtomic: { entered: enteredResolve, gate, when: 2 }
  });
  const v2First = setup({ idb });
  const prepared = await v2First.boundary.prepare(fixtureOuter.content);
  const authorizationWire = await outerFor(prepared);
  const claimWork = v2First.boundary.claimSigningAttempt(authorizationWire);
  await entered;
  const transition = idb.writeDevice(transitioned);
  release();
  await assert.rejects(claimWork, unavailable);
  await transition;
  const durableClaim = idb.stored().signingClaim;
  assert.equal(typeof durableClaim, "string");
  await assert.rejects(
    v2First.boundary.readSignedAttempt(authorizationWire),
    unavailable
  );
  assert.equal(idb.stored().signingClaim, durableClaim);

  const concurrent = setup();
  const concurrentPrepared = await concurrent.boundary.prepare(
    fixtureOuter.content
  );
  const concurrentWire = await outerFor(concurrentPrepared);
  const outcomes = await Promise.all([
    concurrent.boundary.claimSigningAttempt(concurrentWire),
    setup({ idb: concurrent.idb }).boundary.claimSigningAttempt(concurrentWire)
  ]);
  assert.deepEqual(outcomes.map(({ status }) => status).sort(), [
    "ambiguous", "claimed"
  ]);
  assert.equal(
    outcomes[0].signingClaimWire,
    outcomes[1].signingClaimWire
  );
});

test("transition-first atomic claim through the real seam never reaches a provider", async () => {
  const transitioned = pendingLocal({
    pendingProposal: null,
    state: "revoked"
  });
  const idb = idbHarness({
    beforeAtomic(control) {
      if (control.count === 2) {
        control.write("device", "current", transitioned);
      }
    }
  });
  const instance = setup({ idb });
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const authorizationWire = await outerFor(prepared);
  const authorizationDigest = await authorizationDigestV2(
    authorizationWire,
    { subject, proposal, cryptoImpl: webcrypto }
  );
  let resolveCalls = 0;
  let getPublicKeyCalls = 0;
  let signEventCalls = 0;
  const controller = createDesktopPreEnrollmentApprovalV2({
    enabled: true,
    getContext: () => ({
      access: "full",
      authorizationDigest,
      pairingId: fixturePre.pairingId,
      revision,
      subject
    }),
    readX25519Pending: async () => pendingFromDevice(idb.device()),
    keyBoundary: instance.boundary,
    resolveProvider: () => {
      resolveCalls += 1;
      return {
        async getPublicKey() {
          getPublicKeyCalls += 1;
          return subject;
        },
        async signEvent() {
          signEventCalls += 1;
          return signedEventFor(authorizationWire);
        }
      };
    },
    nowMs: () => fixturePre.issuedAt,
    cryptoImpl: webcrypto
  });
  await assert.rejects(controller.approve({
    authorizationWire,
    comparisonCode: preEnrollmentComparisonCode(authorizationDigest),
    proposal
  }), seamUnavailable);
  assert.deepEqual({ resolveCalls, getPublicKeyCalls, signEventCalls }, {
    resolveCalls: 0,
    getPublicKeyCalls: 0,
    signEventCalls: 0
  });
  assert.equal(idb.stored().signingClaim, null);
});

test("context switch at the final claim put boundary commits no claim", async () => {
  const contextState = { subjectHint: subject, revision };
  let switchAtPut = false;
  let switched = 0;
  const idb = idbHarness({
    beforePut({ storeName, value }) {
      if (
        switchAtPut && storeName === "provisional-authentication-key-v2" &&
        value.signingClaim !== null
      ) {
        switched += 1;
        contextState.revision = "bb".repeat(32);
      }
    }
  });
  const instance = setup({ idb, contextState });
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const authorizationWire = await outerFor(prepared);
  const before = idb.device();
  switchAtPut = true;
  await assert.rejects(
    instance.boundary.claimSigningAttempt(authorizationWire),
    unavailable
  );
  assert.equal(switched, 1);
  assert.equal(idb.stored().signingClaim, null);
  assert.deepEqual(idb.device(), before);
});

test("claim CAS reread rejects protected schema, state, revision and transcript changes", async () => {
  const corruptions = [
    ["schema", (record) => ({ ...record, schema: "wrong" })],
    ["state", (record) => ({ ...record, state: "wrong" })],
    ["revision", (record) => ({
      ...record,
      recordRevision: "ff".repeat(32)
    })],
    ["transcript", (record) => ({
      ...record,
      bindingAuthorizationDigest: "00".repeat(32)
    })]
  ];
  for (const [name, corrupt] of corruptions) {
    const idb = idbHarness({
      beforeAtomic(control) {
        if (control.count !== 2) return;
        const record = control.read(
          "provisional-authentication-key-v2",
          proposal.deviceId
        );
        control.write(
          "provisional-authentication-key-v2",
          proposal.deviceId,
          corrupt(record)
        );
      }
    });
    const instance = setup({ idb });
    const prepared = await instance.boundary.prepare(fixtureOuter.content);
    const authorizationWire = await outerFor(prepared);
    const x25519Before = idb.device();
    await assert.rejects(
      instance.boundary.claimSigningAttempt(authorizationWire),
      unavailable,
      name
    );
    assert.equal(idb.stored().signingClaim, null, name);
    assert.deepEqual(idb.device(), x25519Before, name);
  }
});

test("real key boundary durably retains signer-return evidence across live-state races", async (t) => {
  for (const race of [
    "session-revision", "logged-out", "subject-switch", "pending-source",
    "cancellation"
  ]) {
    await t.test(race, async () => {
      const keyContext = { subjectHint: subject, revision };
      const instance = setup({ contextState: keyContext });
      const prepared = await instance.boundary.prepare(fixtureOuter.content);
      const authorizationWire = await outerFor(prepared);
      const authorizationDigest = await authorizationDigestV2(
        authorizationWire,
        { subject, proposal, cryptoImpl: webcrypto }
      );
      const signedEvent = await signedEventFor(authorizationWire);
      const seamContext = {
        access: "full",
        authorizationDigest,
        pairingId: fixturePre.pairingId,
        revision,
        subject
      };
      let signCalls = 0;
      let resolveCalls = 0;
      let controller;
      const createController = (onSign, providerMustStayClosed = false) =>
        createDesktopPreEnrollmentApprovalV2({
          enabled: true,
          getContext: () => ({ ...seamContext }),
          readX25519Pending: async () => pendingFromDevice(instance.idb.device()),
          keyBoundary: instance.boundary,
          resolveProvider: () => {
            resolveCalls += 1;
            if (providerMustStayClosed) {
              throw new Error("NIP-07 must not be reacquired");
            }
            return {
              async getPublicKey() { return subject; },
              async signEvent() {
                signCalls += 1;
                onSign();
                return signedEvent;
              }
            };
          },
          nowMs: () => fixturePre.issuedAt,
          cryptoImpl: webcrypto
        });
      controller = createController(() => {
        if (race === "session-revision") {
          keyContext.revision = "bb".repeat(32);
          seamContext.revision = keyContext.revision;
        } else if (race === "logged-out") {
          seamContext.access = "limited";
        } else if (race === "subject-switch") {
          keyContext.subjectHint = "11".repeat(32);
          seamContext.subject = keyContext.subjectHint;
        } else if (race === "pending-source") {
          instance.idb.replaceDevice(pendingLocal({
            requestId: "ff".repeat(32)
          }));
        } else {
          controller.cancel();
        }
      });
      const approve = (value) => value.approve({
        authorizationWire,
        comparisonCode: preEnrollmentComparisonCode(authorizationDigest),
        proposal
      });
      await assert.rejects(approve(controller), seamUnavailable);
      assert.equal(signCalls, 1);
      const stored = instance.idb.stored();
      assert.equal(typeof stored.signedAttempt, "string");
      assert.equal(await instance.boundary.persistSignedAttempt(
        stored.signingClaim,
        stored.signedAttempt
      ), stored.signedAttempt);

      const callsBeforeRetry = { resolveCalls, signCalls };
      if (race === "pending-source") {
        const retry = createController(() => {}, true);
        await assert.rejects(approve(retry), seamUnavailable);
        assert.deepEqual({ resolveCalls, signCalls }, callsBeforeRetry);
        instance.idb.replaceDevice(pendingLocal());
        assert.equal(await instance.boundary.readSignedAttempt(authorizationWire),
          stored.signedAttempt);
      } else if (race === "cancellation") {
        await assert.rejects(approve(controller), seamUnavailable);
        assert.deepEqual({ resolveCalls, signCalls }, callsBeforeRetry);
        const reopened = createController(() => {}, true);
        assert.equal(await approve(reopened), stored.signedAttempt);
        assert.deepEqual({ resolveCalls, signCalls }, callsBeforeRetry);
      } else {
        keyContext.subjectHint = subject;
        keyContext.revision = revision;
        seamContext.access = "full";
        seamContext.subject = subject;
        seamContext.revision = revision;
        const reopened = createController(() => {}, true);
        assert.equal(await approve(reopened), stored.signedAttempt);
        assert.deepEqual({ resolveCalls, signCalls }, callsBeforeRetry);
      }
    });
  }
});

test("evidence-only persistence rejects every non-identical claim and CAS identity", async () => {
  const instance = setup();
  const prepared = await instance.boundary.prepare(fixtureOuter.content);
  const authorizationWire = await outerFor(prepared);
  const claim = await instance.boundary.claimSigningAttempt(authorizationWire);
  const signedEvent = await signedEventFor(authorizationWire);
  const signedAttemptWire = await createSignedAttemptV2(
    authorizationWire,
    signedEvent,
    { subject, proposal, cryptoImpl: webcrypto }
  );
  const claimValue = JSON.parse(claim.signingClaimWire);
  const attemptValue = JSON.parse(signedAttemptWire);
  for (const [name, claimWire, attemptWire] of [
    ["claim", changedWire(claim.signingClaimWire, {
      authorizationDigest: "00".repeat(32)
    }), signedAttemptWire],
    ["event", claim.signingClaimWire, changedWire(signedAttemptWire, {
      approvalEventId: "00".repeat(32)
    })],
    ["subject", changedWire(claim.signingClaimWire, {
      subject: "11".repeat(32)
    }), signedAttemptWire],
    ["revision", changedWire(claim.signingClaimWire, {
      recordRevision: "ff".repeat(32)
    }), signedAttemptWire]
  ]) {
    await assert.rejects(
      instance.boundary.persistSignedAttempt(claimWire, attemptWire),
      unavailable,
      name
    );
    assert.equal(instance.idb.stored().signedAttempt, null, name);
  }
  assert.equal(claimValue.authorizationWire, authorizationWire);
  assert.equal(attemptValue.authorizationWire, authorizationWire);
  const stored = instance.idb.stored();
  instance.idb.replace(proposal.deviceId, {
    ...stored,
    pendingProposal: JSON.stringify({
      ...JSON.parse(stored.pendingProposal),
      publicKey: "10" + "00".repeat(31)
    })
  });
  await assert.rejects(instance.boundary.persistSignedAttempt(
    claim.signingClaimWire,
    signedAttemptWire
  ), unavailable, "proposal");
  assert.equal(instance.idb.stored().signedAttempt, null);
});

test("non-strict durability and IndexedDB absence fail closed without key export", async () => {
  await assert.rejects(setup({
    idb: idbHarness({ durability: "default" })
  }).boundary.prepare(fixtureOuter.content), unavailable);
  const absent = createMessagingDeviceEd25519KeyV2({
    getContext: () => ({ revision, subjectHint: subject }),
    indexedDBImpl: null,
    cryptoImpl: webcrypto,
    CryptoKeyImpl: NativeCryptoKey
  });
  await assert.rejects(absent.prepare(fixtureOuter.content), unavailable);
});

test("whole-argument proxy/getter failures at key-boundary construction are redacted", () => {
  const secret = "key-boundary-constructor-secret";
  const poison = new Proxy({}, {
    ownKeys() { throw new Error(secret); }
  });
  let error;
  try { createMessagingDeviceEd25519KeyV2(poison); }
  catch (caught) { error = caught; }
  assert.equal(error?.constructor, Error);
  assert.equal(error?.message,
    "messaging device provisional authentication key unavailable");
  assert.equal(String(error).includes(secret), false);
  assert.equal(Object.hasOwn(error, "cause"), false);
});

test("source has no promotion, accepted state, private export, transport or old V2 database", async () => {
  const source = await readFile(new URL(
    "../web/messaging-device-ed25519-key-v2.mjs",
    import.meta.url
  ), "utf8");
  assert.doesNotMatch(source,
    /hodlxxi-social-messaging-device-ed25519-key-v2|STORE_KEY|localStorage|sessionStorage|fetch\(|XMLHttpRequest|WebSocket|pkcs8|jwk/);
  assert.doesNotMatch(source, /\bpromote\b|state:\s*["']ready|state:\s*["']accepted/);
  assert.deepEqual(Object.keys(setup().boundary).sort(), [
    "claimSigningAttempt", "createEnrollmentProofV2", "persistSignedAttempt",
    "prepare", "readSignedAttempt"
  ]);
});
