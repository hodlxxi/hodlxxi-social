import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256
} from "../web/vendor/hpke-core-v1.9.0.mjs";
import {
  createMessageEnvelopeEncryptorForTest,
  encryptMessageEnvelope,
  MAX_PLAINTEXT_BYTES,
  MAX_RECIPIENT_CLOCK_SKEW_MS,
  MESSAGE_ENVELOPE_SCHEMA,
  MESSAGE_ENVELOPE_SUITE
} from "../web/message-encryption-v128e.mjs";

// Node 18 exposes the same native WebCrypto implementation behind node:crypto;
// install the browser-shaped global used by the production bundle for this
// isolated test process. No algorithm fallback is supplied.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: webcrypto
  });
}

const now = 1_788_652_800_000;
const plaintext = "V1.28E private message — Καλημέρα ₿";
const alias = "p_KHcJHzAgVKtH830W3gJGIg";
const packageSchema = "hodlxxi.social_messaging_recipient_package.v1";
const wrapDomain = "HODLXXI_SOCIAL_MESSAGE_KEY_WRAP_V1";
const bodyAlgorithm = "aes-256-gcm";
const wrapAlgorithm = "hpke-base-x25519-hkdfsha256-aes128gcm-v1";
const handles = [
  "d_AAAAAAAAAAAAAAAAAAAAAA",
  "d_BBBBBBBBBBBBBBBBBBBBBB",
  "d_CCCCCCCCCCCCCCCCCCCCCC"
];

const suite = () => new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm()
});

const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");
const hexToBytes = (value) => Uint8Array.from(
  value.match(/../gu),
  (byte) => Number.parseInt(byte, 16)
);
const decode64 = (value) => {
  assert.match(value, /^[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(value, /=/);
  return new Uint8Array(Buffer.from(value, "base64url"));
};

const packageSnapshotId = (record) => {
  const evidence = {
    alias: record.alias,
    complete: true,
    devices: record.devices.map((device) => ({
      algorithm: device.algorithm,
      deviceHandle: device.deviceHandle,
      expiresAt: device.expiresAt,
      publicKey: device.publicKey,
      validFrom: device.validFrom,
      version: device.version
    })),
    expiresAt: record.expiresAt,
    issuedAt: record.issuedAt,
    schema: packageSchema,
    source: "hodlxxi-ubid",
    version: 1
  };
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(evidence), "ascii")
    .digest("hex")}`;
};

async function fixtures() {
  const pairs = [];
  const devices = [];
  for (let index = 0; index < handles.length; index += 1) {
    const pair = await webcrypto.subtle.generateKey(
      { name: "X25519" },
      false,
      ["deriveBits"]
    );
    pairs.push(pair);
    devices.push({
      deviceHandle: handles[index],
      algorithm: "x25519-v1",
      version: index + 1,
      publicKey: bytesToHex(
        new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey))
      ),
      validFrom: now - 60_000,
      expiresAt: now + 300_000
    });
  }
  const recipientPackage = {
    schema: packageSchema,
    version: 1,
    source: "hodlxxi-ubid",
    snapshotId: "",
    complete: true,
    alias,
    issuedAt: now - 10_000,
    expiresAt: now + 60_000,
    devices
  };
  recipientPackage.snapshotId = packageSnapshotId(recipientPackage);
  return { recipientPackage, pairs };
}

const fixture = await fixtures();
const clonePackage = () => structuredClone(fixture.recipientPackage);
const refreshedPackage = (mutate) => {
  const recipientPackage = clonePackage();
  mutate(recipientPackage);
  recipientPackage.snapshotId = packageSnapshotId(recipientPackage);
  return recipientPackage;
};
const encryptAtFixtureTime = createMessageEnvelopeEncryptorForTest({
  cryptoImpl: webcrypto,
  now: () => now
});

function headerBytes(envelope) {
  return new TextEncoder().encode(
    `{"schema":${JSON.stringify(envelope.schema)}` +
    `,"version":${JSON.stringify(envelope.version)}` +
    `,"suite":${JSON.stringify(envelope.suite)}` +
    `,"messageId":${JSON.stringify(envelope.messageId)}` +
    `,"recipientPackageSnapshotId":${JSON.stringify(envelope.recipientPackageSnapshotId)}` +
    `,"recipientDeviceHandles":${JSON.stringify(envelope.recipientDeviceHandles)}` +
    `,"bodyAlgorithm":${JSON.stringify(envelope.body.algorithm)}}`
  );
}

const hpkeInfo = (messageId) =>
  new TextEncoder().encode(`${wrapDomain}\u0000${messageId}`);

function hpkeAad(envelope, deviceHandle) {
  const header = headerBytes(envelope);
  const handle = new TextEncoder().encode(deviceHandle);
  const result = new Uint8Array(header.length + 1 + handle.length);
  result.set(header);
  result.set(handle, header.length + 1);
  return result;
}

async function unwrap(envelope, index, deviceHandle = handles[index]) {
  const wrap = envelope.keyWraps.find((candidate) =>
    candidate.deviceHandle === deviceHandle
  );
  assert.ok(wrap);
  return new Uint8Array(await suite().open(
    {
      recipientKey: fixture.pairs[index].privateKey,
      enc: decode64(wrap.enc),
      info: hpkeInfo(envelope.messageId)
    },
    decode64(wrap.ciphertext),
    hpkeAad(envelope, deviceHandle)
  ));
}

async function decryptBody(envelope, messageKey) {
  const key = await webcrypto.subtle.importKey(
    "raw",
    messageKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  return new TextDecoder().decode(await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: decode64(envelope.body.nonce),
      additionalData: headerBytes(envelope),
      tagLength: 128
    },
    key,
    decode64(envelope.body.ciphertext)
  ));
}

test("accepts the exact fresh V1.28D recipient-package contract", async () => {
  const envelope = await encryptAtFixtureTime({
    recipientPackage: clonePackage(),
    plaintext
  });
  assert.equal(envelope.schema, MESSAGE_ENVELOPE_SCHEMA);
  assert.equal(envelope.version, 1);
  assert.equal(envelope.recipientPackageSnapshotId, fixture.recipientPackage.snapshotId);
  assert.deepEqual(envelope.recipientDeviceHandles, handles);
});

test("recipient package future skew accepts exactly 30 seconds and rejects the next millisecond", async () => {
  assert.equal(MAX_RECIPIENT_CLOCK_SKEW_MS, 30_000);
  for (const [label, issuedAt, accepted] of [
    ["synchronized", now, true],
    ["exact allowance", now + MAX_RECIPIENT_CLOCK_SKEW_MS, true],
    ["beyond allowance", now + MAX_RECIPIENT_CLOCK_SKEW_MS + 1, false]
  ]) {
    const recipientPackage = refreshedPackage((value) => {
      value.issuedAt = issuedAt;
    });
    const operation = encryptAtFixtureTime({ recipientPackage, plaintext });
    if (accepted) await assert.doesNotReject(operation, label);
    else await assert.rejects(operation, /message encryption unavailable/, label);
  }
});

test("recipient package expiry skew tolerates less than 30 seconds but rejects at and beyond the boundary", async () => {
  for (const [label, expiryOffset, accepted] of [
    ["inside allowance", -MAX_RECIPIENT_CLOCK_SKEW_MS + 1, true],
    ["exact rejection boundary", -MAX_RECIPIENT_CLOCK_SKEW_MS, false],
    ["beyond rejection boundary", -MAX_RECIPIENT_CLOCK_SKEW_MS - 1, false]
  ]) {
    const recipientPackage = refreshedPackage((value) => {
      value.expiresAt = now + expiryOffset;
      value.issuedAt = value.expiresAt - 60_000;
      for (const device of value.devices) device.validFrom = value.issuedAt - 1;
    });
    const operation = encryptAtFixtureTime({ recipientPackage, plaintext });
    if (accepted) await assert.doesNotReject(operation, label);
    else await assert.rejects(operation, /message encryption unavailable/, label);
  }
});

test("recipient device expiry uses the same exact skew boundary while preserving package containment", async () => {
  for (const [label, expiryOffset, accepted] of [
    ["inside allowance", -MAX_RECIPIENT_CLOCK_SKEW_MS + 1, true],
    ["exact rejection boundary", -MAX_RECIPIENT_CLOCK_SKEW_MS, false]
  ]) {
    const recipientPackage = refreshedPackage((value) => {
      value.expiresAt = now + expiryOffset;
      value.issuedAt = value.expiresAt - 60_000;
      for (const device of value.devices) {
        device.validFrom = value.issuedAt - 1;
        device.expiresAt = value.expiresAt;
      }
    });
    const operation = encryptAtFixtureTime({ recipientPackage, plaintext });
    if (accepted) await assert.doesNotReject(operation, label);
    else await assert.rejects(operation, /message encryption unavailable/, label);
  }
});

test("clock skew does not weaken malformed stale or snapshot-mismatched evidence rejection", async () => {
  const stale = refreshedPackage((value) => {
    value.expiresAt = now - MAX_RECIPIENT_CLOCK_SKEW_MS;
    value.issuedAt = value.expiresAt - 60_000;
    for (const device of value.devices) device.validFrom = value.issuedAt - 1;
  });
  await assert.rejects(
    encryptAtFixtureTime({ recipientPackage: stale, plaintext }),
    /message encryption unavailable/
  );

  const malformed = refreshedPackage((value) => {
    value.issuedAt = String(value.issuedAt);
  });
  await assert.rejects(
    encryptAtFixtureTime({ recipientPackage: malformed, plaintext }),
    /message encryption unavailable/
  );

  const snapshotMismatch = clonePackage();
  snapshotMismatch.expiresAt += 1;
  await assert.rejects(
    encryptAtFixtureTime({ recipientPackage: snapshotMismatch, plaintext }),
    /message encryption unavailable/
  );
});

test("recipient timestamps remain explicit Unix milliseconds with no magnitude guessing", async () => {
  const secondsInsteadOfMilliseconds = refreshedPackage((value) => {
    value.issuedAt = Math.floor(value.issuedAt / 1000);
    value.expiresAt = Math.floor(value.expiresAt / 1000);
    for (const device of value.devices) {
      device.validFrom = Math.floor(device.validFrom / 1000);
      device.expiresAt = Math.floor(device.expiresAt / 1000);
    }
  });
  await assert.rejects(
    encryptAtFixtureTime({
      recipientPackage: secondsInsteadOfMilliseconds,
      plaintext
    }),
    /message encryption unavailable/
  );

  const source = await readFile(
    new URL("../web/message-encryption-v128e.mjs", import.meta.url),
    "utf8"
  );
  assert.match(source, /record\.issuedAt > now \+ MAX_RECIPIENT_CLOCK_SKEW_MS/);
  assert.equal(
    [...source.matchAll(/record\.expiresAt <= now - MAX_RECIPIENT_CLOCK_SKEW_MS/g)].length,
    2
  );
  assert.doesNotMatch(
    source,
    /Date\([^)]*(?:issuedAt|expiresAt)|(?:issuedAt|expiresAt)\s*[/*]\s*1000/
  );
});

test("malformed, duplicate, stale, expired, empty and oversized packages fail closed", async () => {
  const cases = [];
  const add = (label, mutate) => {
    const value = clonePackage();
    mutate(value);
    cases.push([label, value]);
  };
  add("zero devices", (value) => { value.devices = []; });
  add("more than sixteen devices", (value) => {
    value.devices = Array.from({ length: 17 }, (_, index) => ({
      ...value.devices[0],
      deviceHandle: `d_${String(index).padStart(22, "A")}`,
      publicKey: index.toString(16).padStart(64, "0")
    }));
  });
  add("unknown field", (value) => { value.canonicalSubject = "a".repeat(64); });
  add("wrong schema", (value) => { value.schema = "unknown"; });
  add("wrong source", (value) => { value.source = "other"; });
  add("wrong version", (value) => { value.version = 2; });
  add("incomplete", (value) => { value.complete = false; });
  add("malformed alias", (value) => { value.alias = "p_invalid"; });
  add("future package", (value) => { value.issuedAt = now + 1; });
  add("expired package", (value) => { value.expiresAt = now; });
  add("inconsistent package validity", (value) => { value.expiresAt = value.issuedAt; });
  add("expired device", (value) => { value.devices[0].expiresAt = now; });
  add("future device", (value) => { value.devices[0].validFrom = value.issuedAt + 1; });
  add("device does not cover package", (value) => { value.devices[0].expiresAt = value.expiresAt - 1; });
  add("duplicate handle", (value) => { value.devices[1].deviceHandle = value.devices[0].deviceHandle; });
  add("duplicate public key", (value) => { value.devices[1].publicKey = value.devices[0].publicKey; });
  add("unsorted handles", (value) => { value.devices.reverse(); });
  add("unknown device field", (value) => { value.devices[0].deviceId = "fixture-device-id"; });
  add("wrong algorithm", (value) => { value.devices[0].algorithm = "unknown"; });
  add("bad binding version", (value) => { value.devices[0].version = 0; });
  add("zero X25519 key", (value) => { value.devices[0].publicKey = "00".repeat(32); });
  add("non-canonical X25519 key", (value) => { value.devices[0].publicKey = "ff".repeat(32); });
  add("uppercase X25519 key", (value) => { value.devices[0].publicKey = value.devices[0].publicKey.toUpperCase(); });
  add("changed snapshot evidence", (value) => { value.devices[0].version += 1; });
  add("malformed snapshot", (value) => { value.snapshotId = "sha256:" + "A".repeat(64); });

  for (const [label, recipientPackage] of cases) {
    await assert.rejects(
      encryptAtFixtureTime({ recipientPackage, plaintext }),
      (error) => error?.message === "message encryption unavailable",
      label
    );
  }
});

test("plaintext input is text-only, non-empty, UTF-8 byte bounded and production input is closed", async () => {
  assert.equal(MAX_PLAINTEXT_BYTES, 16384);
  for (const invalid of [undefined, null, 1, {}, "", "€".repeat(5462)]) {
    await assert.rejects(
      encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext: invalid }),
      /message encryption unavailable/
    );
  }
  await assert.doesNotReject(encryptAtFixtureTime({
    recipientPackage: clonePackage(),
    plaintext: "a".repeat(MAX_PLAINTEXT_BYTES)
  }));
  await assert.rejects(encryptAtFixtureTime({
    recipientPackage: clonePackage(),
    plaintext,
    messageId: `m_${"A".repeat(43)}`
  }), /message encryption unavailable/);
});

test("one body encryption and one independent one-shot HPKE wrap serve every recipient device", async () => {
  let bodyEncryptions = 0;
  const bodyImports = [];
  const bodyCrypto = {
    getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
    subtle: {
      digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
      importKey: async (...arguments_) => {
        bodyImports.push(arguments_);
        return webcrypto.subtle.importKey(...arguments_);
      },
      encrypt: async (...arguments_) => {
        bodyEncryptions += 1;
        return webcrypto.subtle.encrypt(...arguments_);
      }
    }
  };
  const created = [];
  const encrypt = createMessageEnvelopeEncryptorForTest({
    cryptoImpl: bodyCrypto,
    now: () => now,
    hpkeSuiteFactory: () => {
      const delegate = suite();
      const instance = { seals: 0 };
      created.push(instance);
      return {
        kem: delegate.kem,
        async seal(...arguments_) {
          instance.seals += 1;
          assert.equal(instance.seals, 1, "a context factory result is one-shot");
          return delegate.seal(...arguments_);
        }
      };
    }
  });
  const envelope = await encrypt({ recipientPackage: clonePackage(), plaintext });
  assert.equal(bodyEncryptions, 1);
  assert.equal(bodyImports.length, 1);
  assert.equal(bodyImports[0][0], "raw");
  assert.equal(bodyImports[0][1].byteLength, 32);
  assert.deepEqual(bodyImports[0][2], { name: "AES-GCM", length: 256 });
  assert.equal(bodyImports[0][3], false);
  assert.deepEqual(bodyImports[0][4], ["encrypt"]);
  assert.equal(created.length, handles.length);
  assert.deepEqual(created.map((instance) => instance.seals), [1, 1, 1]);
  assert.equal(envelope.keyWraps.length, handles.length);
  assert.deepEqual(envelope.keyWraps.map((wrap) => wrap.deviceHandle), handles);
});

test("every included device unwraps the same K_message and decrypts the one body", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const recovered = await Promise.all(handles.map((_, index) => unwrap(envelope, index)));
  assert.equal(new Set(recovered.map(bytesToHex)).size, 1);
  for (const messageKey of recovered) {
    assert.equal(messageKey.byteLength, 32);
    assert.equal(await decryptBody(envelope, messageKey), plaintext);
  }
});

test("a device omitted from keyWraps cannot recover K_message", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const outsider = await webcrypto.subtle.generateKey(
    { name: "X25519" }, false, ["deriveBits"]
  );
  const wrap = envelope.keyWraps[0];
  await assert.rejects(suite().open(
    {
      recipientKey: outsider.privateKey,
      enc: decode64(wrap.enc),
      info: hpkeInfo(envelope.messageId)
    },
    decode64(wrap.ciphertext),
    hpkeAad(envelope, wrap.deviceHandle)
  ));
});

test("separate identical plaintext encryptions use fresh identifiers, nonces, ciphertexts and encapsulations", async () => {
  const first = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const second = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  assert.notEqual(first.messageId, second.messageId);
  assert.notEqual(first.body.nonce, second.body.nonce);
  assert.notEqual(first.body.ciphertext, second.body.ciphertext);
  assert.deepEqual(
    first.keyWraps.map((wrap, index) => wrap.enc !== second.keyWraps[index].enc),
    [true, true, true]
  );
});

test("the test seam confirms exactly one 32-byte content key and a 12-byte body nonce draw", async () => {
  const draws = [];
  const encrypt = createMessageEnvelopeEncryptorForTest({
    cryptoImpl: webcrypto,
    now: () => now,
    randomFill: (bytes) => {
      draws.push(bytes);
      bytes.fill(draws.length);
      return bytes;
    }
  });
  const envelope = await encrypt({ recipientPackage: clonePackage(), plaintext });
  assert.deepEqual(draws.map((bytes) => bytes.byteLength), [32, 32, 12]);
  assert.notEqual(draws[0], draws[1]);
  assert.notEqual(draws[1], draws[2]);
  assert.equal(draws[1].every((byte) => byte === 0), true);
  assert.equal(Object.hasOwn(envelope, "messageKey"), false);
  assert.doesNotMatch(JSON.stringify(envelope), /K_message|messageKey/);
});

test("body ciphertext tampering fails authenticated decryption", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const messageKey = await unwrap(envelope, 0);
  const changed = structuredClone(envelope);
  const ciphertext = decode64(changed.body.ciphertext);
  ciphertext[0] ^= 0x80;
  changed.body.ciphertext = Buffer.from(ciphertext).toString("base64url");
  await assert.rejects(decryptBody(changed, messageKey));
});

test("every authenticated header field is bound to body encryption and HPKE unwrap", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const messageKey = await unwrap(envelope, 0);
  const mutations = [
    ["schema", (value) => { value.schema = "hodlxxi.social_message_envelope.changed"; }],
    ["version", (value) => { value.version = 2; }],
    ["suite", (value) => { value.suite += "-changed"; }],
    ["messageId", (value) => { value.messageId = `m_${"A".repeat(43)}`; }],
    ["snapshot", (value) => { value.recipientPackageSnapshotId = "sha256:" + "a".repeat(64); }],
    ["device list", (value) => { value.recipientDeviceHandles = value.recipientDeviceHandles.slice(1); }],
    ["body algorithm", (value) => { value.body.algorithm = "aes-128-gcm"; }]
  ];
  for (const [label, mutate] of mutations) {
    const changed = structuredClone(envelope);
    mutate(changed);
    await assert.rejects(decryptBody(changed, messageKey), undefined, label);
    await assert.rejects(unwrap(changed, 0), undefined, label);
  }
});

test("changing one deviceHandle/keyWrap association breaks unwrap", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  const changed = structuredClone(envelope);
  changed.keyWraps[0].deviceHandle = handles[1];
  changed.keyWraps[1].deviceHandle = handles[0];
  await assert.rejects(unwrap(changed, 0));
  await assert.rejects(unwrap(changed, 1));
});

test("the frozen envelope has exact closed fields, strict binary encodings and no sensitive inputs", async () => {
  const envelope = await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
  assert.deepEqual(Object.keys(envelope), [
    "schema", "version", "suite", "messageId",
    "recipientPackageSnapshotId", "recipientDeviceHandles", "body", "keyWraps"
  ]);
  assert.deepEqual(Object.keys(envelope.body), ["algorithm", "nonce", "ciphertext"]);
  assert.equal(envelope.body.algorithm, bodyAlgorithm);
  assert.match(envelope.messageId, /^m_[A-Za-z0-9_-]{43}$/);
  assert.equal(decode64(envelope.messageId.slice(2)).byteLength, 32);
  assert.equal(decode64(envelope.body.nonce).byteLength, 12);
  assert.equal(
    decode64(envelope.body.ciphertext).byteLength,
    new TextEncoder().encode(plaintext).byteLength + 16
  );
  for (const wrap of envelope.keyWraps) {
    assert.deepEqual(Object.keys(wrap), ["deviceHandle", "algorithm", "enc", "ciphertext"]);
    assert.equal(wrap.algorithm, wrapAlgorithm);
    assert.equal(decode64(wrap.enc).byteLength, 32);
    assert.equal(decode64(wrap.ciphertext).byteLength, 48);
  }
  assert.deepEqual(
    envelope.recipientDeviceHandles,
    [...new Set(envelope.recipientDeviceHandles)].sort()
  );
  assert.deepEqual(
    envelope.keyWraps.map((wrap) => wrap.deviceHandle),
    envelope.recipientDeviceHandles
  );

  const serialized = JSON.stringify(envelope);
  for (const forbidden of [
    plaintext,
    alias,
    "rc_fixture-capability",
    "subject-fixture",
    "deviceId-fixture",
    "bindingId-fixture",
    "private-key-material-fixture",
    "private-label-fixture",
    ...fixture.recipientPackage.devices.map((device) => device.publicKey)
  ]) assert.equal(serialized.includes(forbidden), false, forbidden);
  assert.doesNotMatch(serialized, /(?:plaintext|messageKey|K_message|publicKey|privateKey|alias|capability)/i);
  assert.equal(Object.hasOwn(envelope, "messageKey"), false);
});

test("encryption performs no network or browser persistence operation", async () => {
  const names = [
    "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
    "localStorage", "sessionStorage", "indexedDB"
  ];
  const descriptors = new Map(names.map((name) => [
    name,
    Object.getOwnPropertyDescriptor(globalThis, name)
  ]));
  let accesses = 0;
  try {
    for (const name of names) {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        get() {
          accesses += 1;
          throw new Error("forbidden side effect");
        }
      });
    }
    await encryptAtFixtureTime({ recipientPackage: clonePackage(), plaintext });
    assert.equal(accesses, 0);
  } finally {
    for (const name of names) {
      const descriptor = descriptors.get(name);
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});

test("production source is browser-only and never reaches a sender private key or side-effect API", async () => {
  const [source, bundle] = await Promise.all([
    readFile(new URL("../web/message-encryption-v128e.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/vendor/hpke-core-v1.9.0.mjs", import.meta.url), "utf8")
  ]);
  for (const forbidden of [
    /node:/, /https?:\/\//, /Math\.random/, /randomUUID/,
    /(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(/,
    /(?:localStorage|sessionStorage|indexedDB)\s*[.(]/,
    /messaging-device-v128c1/, /senderKey\s*:/,
    /\.exportKey\s*\(/
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
  assert.doesNotMatch(bundle, /(?:^|[^A-Za-z])import\s*\(/m);
  assert.doesNotMatch(bundle, /node:/);
  assert.doesNotMatch(bundle, /https?:\/\//);
  assert.match(source, /globalThis\.crypto\.getRandomValues/);
  assert.match(source, /new CipherSuite/);
  assert.match(source, /await suite\.seal/);
  assert.doesNotMatch(bundle, /^\s*import\s/m);
});

test("dependency and local delivery provenance remain exact and the UI stays inert", async () => {
  const [manifestSource, lockSource, buildSource, entrySource, ciSource] = await Promise.all([
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../package-lock.json", import.meta.url), "utf8"),
    readFile(new URL("../scripts/build-v128e-hpke-browser.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/auth-entry.mjs", import.meta.url), "utf8"),
    readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8")
  ]);
  const manifest = JSON.parse(manifestSource);
  const lock = JSON.parse(lockSource);
  assert.deepEqual(manifest.dependencies, { "@hpke/core": "1.9.0" });
  assert.deepEqual(manifest.devDependencies, { esbuild: "0.28.2" });
  assert.equal(lock.packages["node_modules/@hpke/core"].version, "1.9.0");
  assert.equal(
    lock.packages["node_modules/@hpke/core"].integrity,
    "sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q=="
  );
  assert.equal(lock.packages["node_modules/@hpke/common"].version, "1.10.1");
  assert.equal(lock.packages["node_modules/esbuild"].version, "0.28.2");
  assert.match(buildSource, /platform: "browser"/);
  assert.match(buildSource, /target: \["chrome111"\]/);
  assert.match(buildSource, /disable-node-crypto-fallback/);
  assert.doesNotMatch(buildSource, /https?:\/\//);
  assert.doesNotMatch(entrySource, /message-encryption-v128e|hpke-core-v1\.9\.0/);
  assert.match(ciSource, /npm ci/);
  assert.match(ciSource, /npm run build:v128e-crypto/);
  assert.match(
    ciSource,
    /git diff --exit-code -- package\.json package-lock\.json web\/vendor\/hpke-core-v1\.9\.0\.mjs/
  );
  assert.match(
    ciSource,
    /9f5eb8be623357983b9862b7e2513fad98d4afdc3ccac869bec315eaf40f43dc/
  );
  assert.match(ciSource, /node-version: "18"/);
  assert.match(ciSource, /node tests\/v128e-browser-message-encryption\.test\.mjs/);
  assert.match(ciSource, /native WebCrypto safely exports only the public X25519 key/);
});

test("official RFC 9180 Base/X25519/HKDF-SHA256/AES-128-GCM vector is compatible", async () => {
  // CFRG RFC 9180 test-vectors.json, mode=0, kem_id=32, kdf_id=1,
  // aead_id=1. Retrieved 2026-09-08; complete source SHA-256:
  // 61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6.
  const vector = {
    info: "4f6465206f6e2061204772656369616e2055726e",
    ikmR: "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
    ikmE: "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
    enc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    aad: "436f756e742d30",
    plaintext: "4265617574792069732074727574682c20747275746820626561757479",
    ciphertext: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
  };
  const cipherSuite = suite();
  const recipient = await cipherSuite.kem.deriveKeyPair(hexToBytes(vector.ikmR));
  const sender = await cipherSuite.createSenderContext({
    recipientPublicKey: recipient.publicKey,
    info: hexToBytes(vector.info),
    ekm: hexToBytes(vector.ikmE)
  });
  assert.equal(bytesToHex(new Uint8Array(sender.enc)), vector.enc);
  assert.equal(bytesToHex(new Uint8Array(await sender.seal(
    hexToBytes(vector.plaintext),
    hexToBytes(vector.aad)
  ))), vector.ciphertext);

  const opener = await cipherSuite.createRecipientContext({
    recipientKey: recipient.privateKey,
    enc: hexToBytes(vector.enc),
    info: hexToBytes(vector.info)
  });
  assert.equal(bytesToHex(new Uint8Array(await opener.open(
    hexToBytes(vector.ciphertext),
    hexToBytes(vector.aad)
  ))), vector.plaintext);
});

test("ordinary production API uses native browser defaults", async () => {
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  try {
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: webcrypto
    });
    const recipientPackage = clonePackage();
    const current = Date.now();
    recipientPackage.issuedAt = current - 1_000;
    recipientPackage.expiresAt = current + 60_000;
    for (const device of recipientPackage.devices) {
      device.validFrom = current - 2_000;
      device.expiresAt = current + 120_000;
    }
    recipientPackage.snapshotId = packageSnapshotId(recipientPackage);
    const envelope = await encryptMessageEnvelope({ recipientPackage, plaintext });
    assert.equal(envelope.schema, MESSAGE_ENVELOPE_SCHEMA);
    assert.equal(envelope.suite, MESSAGE_ENVELOPE_SUITE);
  } finally {
    if (cryptoDescriptor) Object.defineProperty(globalThis, "crypto", cryptoDescriptor);
    else delete globalThis.crypto;
  }
});
