import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  MESSAGING_DEVICE_ED25519_KEY_RUNTIME_ENABLED,
  createMessagingDeviceEd25519KeyV1
} from "../web/messaging-device-ed25519-key-v1.mjs";

const NativeCryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
const SUBJECT = "11".repeat(32);
const OTHER_SUBJECT = "22".repeat(32);
const DEVICE = "33".repeat(32);
const OTHER_DEVICE = "44".repeat(32);
const BINDING_ID = "55".repeat(32);
const OTHER_BINDING_ID = "66".repeat(32);
const X25519_PUBLIC_KEY = "77".repeat(32);
const OTHER_X25519_PUBLIC_KEY = "88".repeat(32);
const CHALLENGE_ID = "99".repeat(32);
const NOW = 1_800_000_000_000;
const PROFILE =
  "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1";
const encoder = new TextEncoder();
const canonical = (value) => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]))
);
const hexBytes = (bytes) => Buffer.from(bytes).toString("hex");
const digest = (domain, source) => createHash("sha256")
  .update(domain + "\0", "ascii")
  .update(source, "ascii")
  .digest("hex");
const unavailable = {
  name: "Error",
  message: "messaging device authentication key unavailable"
};

function binding({
  subject = SUBJECT,
  deviceId = DEVICE,
  bindingId = BINDING_ID,
  bindingVersion = 1,
  publicKey = X25519_PUBLIC_KEY
} = {}) {
  return {
    schema: "hodlxxi.social_messaging_device_local.v1",
    version: 1,
    subject,
    deviceId,
    privateKey: null,
    publicKey,
    requestId: "aa".repeat(32),
    state: "ready",
    acceptedBinding: {
      bindingId,
      version: bindingVersion,
      validFrom: NOW - 60_000,
      expiresAt: NOW + 60_000
    },
    authorization: null,
    pendingAuthorization: null,
    rotation: null,
    pendingProposal: null
  };
}

function enrollmentWire(key, changes = {}) {
  return canonical({
    audience: "https://social.example",
    deviceId: key.deviceId,
    domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2",
    ed25519PublicKey: key.ed25519PublicKey,
    enrollmentChallengeId: CHALLENGE_ID,
    expiresAt: NOW + 30_000,
    issuedAt: NOW - 1_000,
    profile: PROFILE,
    schema: "hodlxxi.social_messaging_device_enrollment.v2",
    subject: key.subject,
    version: 2,
    x25519BindingId: key.x25519BindingId,
    x25519BindingVersion: key.x25519BindingVersion,
    x25519PublicKeyCommitment: key.x25519PublicKeyCommitment,
    ...changes
  });
}

function enrollmentPreimage(wire, publicKey) {
  return canonical({
    domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2",
    enrollment: wire,
    profile: PROFILE,
    publicKey,
    schema: "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2",
    version: 2
  });
}

function parseProof(wire) {
  const proof = JSON.parse(wire);
  assert.equal(canonical(proof), wire);
  assert.deepEqual(Object.keys(proof).sort(), [
    "algorithm", "enrollmentChallengeId", "enrollmentDigest", "profile",
    "publicKey", "schema", "signature", "version"
  ]);
  return proof;
}

async function verifyProofWithWebCrypto(enrollment, proofWire) {
  const proof = parseProof(proofWire);
  const publicKey = await webcrypto.subtle.importKey(
    "raw",
    Buffer.from(proof.publicKey, "hex"),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  assert.equal(await webcrypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    Buffer.from(proof.signature, "hex"),
    encoder.encode(enrollmentPreimage(enrollment, proof.publicKey))
  ), true);
  assert.equal(proof.algorithm, "Ed25519");
  assert.equal(
    proof.enrollmentChallengeId,
    JSON.parse(enrollment).enrollmentChallengeId
  );
  assert.equal(proof.enrollmentDigest,
    "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
    digest("HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2", enrollment));
  assert.equal(proof.profile, PROFILE);
  assert.equal(proof.schema,
    "hodlxxi.social_messaging_device_enrollment_proof.v2");
  assert.equal(proof.version, 2);
  assert.match(proof.signature, /^[0-9a-f]{128}$/);
  return proof;
}

// Event-driven IndexedDB model with serialized transactions. Structured clone
// is the only persistence mechanism and preserves native CryptoKey objects.
function idbHarness({ durability = "strict" } = {}) {
  let initialized = false;
  let value;
  let active = false;
  const queue = [];
  const names = [];
  const stores = [];
  const pump = () => {
    if (active || queue.length === 0) return;
    active = true;
    const { mode, tx, operation, request } = queue.shift();
    queueMicrotask(() => {
      if (tx.aborted) {
        active = false;
        pump();
        return;
      }
      if (operation.kind === "get") {
        request.result = value === undefined ? undefined : structuredClone(value);
        request.onsuccess?.();
      } else if (value !== undefined) {
        tx.aborted = true;
        tx.onabort?.();
        active = false;
        pump();
        return;
      } else {
        value = structuredClone(operation.value);
        request.onsuccess?.();
      }
      queueMicrotask(() => {
        if (!tx.aborted) tx.oncomplete?.();
        active = false;
        pump();
      });
    });
  };
  const schedule = (mode, tx, operation) => {
    const request = {};
    queue.push({ mode, tx, operation, request });
    pump();
    return request;
  };
  const factory = {
    open(name, version) {
      names.push([name, version]);
      const db = {
        close() {},
        createObjectStore(storeName) { stores.push(storeName); },
        transaction(storeName, mode, options) {
          assert.equal(storeName, "authentication-key");
          if (mode === "readwrite") {
            assert.deepEqual(options, { durability: "strict" });
          } else {
            assert.equal(mode, "readonly");
            assert.equal(options, undefined);
          }
          const tx = {
            aborted: false,
            durability,
            abort() {
              if (tx.aborted) return;
              tx.aborted = true;
              queueMicrotask(() => tx.onabort?.());
            },
            objectStore() {
              return {
                get(key) {
                  assert.equal(key, "current");
                  return schedule(mode, tx, { kind: "get" });
                },
                add(record, key) {
                  assert.equal(key, "current");
                  return schedule(mode, tx, { kind: "add", value: record });
                }
              };
            }
          };
          return tx;
        }
      };
      const request = { result: db };
      queueMicrotask(() => {
        if (!initialized) {
          request.onupgradeneeded?.();
          initialized = true;
        }
        request.onsuccess?.();
      });
      return request;
    }
  };
  return {
    factory,
    names,
    stores,
    stored: () => value === undefined ? undefined : structuredClone(value)
  };
}

function trackedCrypto({ beforeSign } = {}) {
  const exports = [];
  const subtle = webcrypto.subtle;
  return {
    exports,
    cryptoImpl: {
      subtle: {
        digest: (...args) => subtle.digest(...args),
        generateKey: (...args) => subtle.generateKey(...args),
        async exportKey(format, key) {
          exports.push({ format, type: key?.type });
          assert.equal(format, "raw");
          assert.equal(key?.type, "public");
          return subtle.exportKey(format, key);
        },
        async sign(...args) {
          await beforeSign?.();
          return subtle.sign(...args);
        }
      }
    }
  };
}

function setup({
  idb = idbHarness(),
  x25519Binding = binding(),
  subjectState = { value: SUBJECT },
  crypto = trackedCrypto(),
  readX25519Binding = async () => x25519Binding
} = {}) {
  const controller = createMessagingDeviceEd25519KeyV1({
    getContext: () => ({ access: "full", subject: subjectState.value }),
    readX25519Binding,
    indexedDBImpl: idb.factory,
    cryptoImpl: crypto.cryptoImpl,
    CryptoKeyImpl: NativeCryptoKey,
    now: () => NOW
  });
  return { controller, crypto, idb, subjectState, x25519Binding };
}

const drain = async () => {
  for (let index = 0; index < 20; index += 1) await Promise.resolve();
};

test("frozen proof fixtures and browser/server Enrollment V2 preimage bytes stay unchanged", async () => {
  const profileBytes = await readFile(new URL(
    "./fixtures/social_messaging_device_proof_profile_v1.json",
    import.meta.url
  ));
  const statementBytes = await readFile(new URL(
    "./fixtures/social_device_admission_v1.json",
    import.meta.url
  ));
  assert.equal(profileBytes.byteLength, 35_150);
  assert.equal(createHash("sha256").update(profileBytes).digest("hex"),
    "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477");
  assert.equal(statementBytes.byteLength, 96_928);
  assert.equal(createHash("sha256").update(statementBytes).digest("hex"),
    "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324");
  const fixture = JSON.parse(profileBytes);
  const enrollment = fixture.enrollmentVector;
  assert.equal(
    enrollmentPreimage(
      enrollment.wire,
      JSON.parse(enrollment.wire).ed25519PublicKey
    ),
    enrollment.phoneProofSigningPreimage
  );
});

test("browser signing follows every frozen canonical audience corpus decision", async () => {
  const fixture = JSON.parse(await readFile(new URL(
    "./fixtures/social_messaging_device_proof_profile_v1.json",
    import.meta.url
  )));
  const { controller } = setup();
  const key = await controller.prepare();
  for (const { id, audience, accepted } of fixture.audienceCorpus.cases) {
    const operation = controller.createEnrollmentProofV2(
      enrollmentWire(key, { audience })
    );
    if (accepted) {
      const proof = parseProof(await operation);
      assert.equal(proof.publicKey, key.ed25519PublicKey, id);
    } else {
      await assert.rejects(operation, unavailable, id);
    }
  }
});

test("module stays dormant, separate, browser-local and has no general signer", async () => {
  const source = await readFile(new URL(
    "../web/messaging-device-ed25519-key-v1.mjs",
    import.meta.url
  ), "utf8");
  assert.equal(MESSAGING_DEVICE_ED25519_KEY_RUNTIME_ENABLED, false);
  assert.match(source,
    /hodlxxi-social-messaging-device-ed25519-key-v1/);
  assert.doesNotMatch(source,
    /hodlxxi-social-messaging-device-v1["']/);
  assert.doesNotMatch(source,
    /localStorage|sessionStorage|fetch\(|XMLHttpRequest|WebSocket|console\.|logger|pkcs8|jwk|deriveBits|X25519.*generateKey/i);
  assert.doesNotMatch(source,
    /createDeviceProof|requestProof|signRequest|generalSign|exportPrivate/i);
  const { controller } = setup();
  assert.deepEqual(Object.keys(controller).sort(),
    ["createEnrollmentProofV2", "prepare"]);
});

test("prepare persists one non-extractable signing-only key in its distinct store", async () => {
  const { controller, crypto, idb } = setup();
  const key = await controller.prepare();
  assert.ok(Object.isFrozen(key));
  assert.equal(Object.hasOwn(key, "privateKey"), false);
  assert.equal(key.subject, SUBJECT);
  assert.equal(key.deviceId, DEVICE);
  assert.equal(key.x25519BindingId, BINDING_ID);
  assert.equal(key.x25519BindingVersion, 1);
  assert.match(key.ed25519PublicKey, /^[0-9a-f]{64}$/);
  assert.equal(key.x25519PublicKeyCommitment,
    "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
    digest(
      "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1",
      X25519_PUBLIC_KEY
    ));
  assert.deepEqual(new Set(idb.names.map(([name]) => name)),
    new Set(["hodlxxi-social-messaging-device-ed25519-key-v1"]));
  assert.deepEqual(idb.stores, ["authentication-key"]);
  assert.ok(crypto.exports.length >= 1);
  assert.ok(crypto.exports.every(({ format, type }) =>
    format === "raw" && type === "public"));
  const stored = idb.stored();
  assert.equal(stored.privateKey instanceof NativeCryptoKey, true);
  assert.equal(stored.privateKey.type, "private");
  assert.equal(stored.privateKey.extractable, false);
  assert.deepEqual(stored.privateKey.usages, ["sign"]);
  assert.equal(stored.privateKey.algorithm.name, "Ed25519");
  await assert.rejects(
    webcrypto.subtle.exportKey("pkcs8", stored.privateKey)
  );
  await assert.rejects(
    webcrypto.subtle.exportKey("jwk", stored.privateKey)
  );
});

test("concurrent tabs atomically converge on the one stored key", async () => {
  const idb = idbHarness();
  const first = setup({ idb });
  const second = setup({ idb });
  const [left, right] = await Promise.all([
    first.controller.prepare(),
    second.controller.prepare()
  ]);
  assert.deepEqual(left, right);
  assert.equal(idb.stored().ed25519PublicKey, left.ed25519PublicKey);
  assert.equal(idb.stored().privateKey.extractable, false);
});

test("the same key survives controller reopening and signs only the exact enrollment preimage", async () => {
  const idb = idbHarness();
  const first = setup({ idb });
  const prepared = await first.controller.prepare();
  const enrollment = enrollmentWire(prepared);
  const firstProof = await first.controller.createEnrollmentProofV2(enrollment);
  await verifyProofWithWebCrypto(enrollment, firstProof);

  const reopened = setup({ idb });
  const afterReopen = await reopened.controller.prepare();
  assert.deepEqual(afterReopen, prepared);
  const reopenedProof = await reopened.controller.createEnrollmentProofV2(enrollment);
  assert.equal(reopenedProof, firstProof);
  await verifyProofWithWebCrypto(enrollment, reopenedProof);
});

test("independent phone and tablet stores generate independent keys and proofs", async () => {
  const phone = setup();
  const tablet = setup({
    x25519Binding: binding({
      deviceId: OTHER_DEVICE,
      bindingId: OTHER_BINDING_ID,
      publicKey: OTHER_X25519_PUBLIC_KEY
    })
  });
  const phoneKey = await phone.controller.prepare();
  const tabletKey = await tablet.controller.prepare();
  assert.notEqual(phoneKey.ed25519PublicKey, tabletKey.ed25519PublicKey);
  assert.notEqual(phoneKey.deviceId, tabletKey.deviceId);
  const phoneEnrollment = enrollmentWire(phoneKey);
  const tabletEnrollment = enrollmentWire(tabletKey, {
    enrollmentChallengeId: "ab".repeat(32)
  });
  const phoneProof = await phone.controller.createEnrollmentProofV2(phoneEnrollment);
  const tabletProof = await tablet.controller.createEnrollmentProofV2(tabletEnrollment);
  await verifyProofWithWebCrypto(phoneEnrollment, phoneProof);
  const parsedTablet = await verifyProofWithWebCrypto(
    tabletEnrollment,
    tabletProof
  );
  assert.equal(parsedTablet.enrollmentChallengeId, "ab".repeat(32));
  assert.notEqual(parseProof(phoneProof).signature, parsedTablet.signature);
});

test("WebCrypto phone and tablet outputs pass the existing strict server verifier when installed", async (t) => {
  let server;
  try {
    server = await import("../src/server/messaging-device-proof-profile-v1.mjs");
  } catch (error) {
    if (error?.code === "ERR_MODULE_NOT_FOUND" &&
        String(error.message).includes("@noble/ed25519")) {
      t.skip("@noble/ed25519 is not installed in this worktree");
      return;
    }
    throw error;
  }
  const cases = [
    setup(),
    setup({
      x25519Binding: binding({
        deviceId: OTHER_DEVICE,
        bindingId: OTHER_BINDING_ID,
        publicKey: OTHER_X25519_PUBLIC_KEY
      })
    })
  ];
  for (const instance of cases) {
    const key = await instance.controller.prepare();
    const enrollment = enrollmentWire(key);
    const proofWire = await instance.controller.createEnrollmentProofV2(enrollment);
    const proof = JSON.parse(proofWire);
    const preimage = server.createEnrollmentProofSigningPreimageV2(enrollment);
    assert.equal(preimage, enrollmentPreimage(enrollment, key.ed25519PublicKey));
    assert.equal(server.createEnrollmentProofV2({
      enrollmentChallengeId: proof.enrollmentChallengeId,
      enrollmentDigest: proof.enrollmentDigest,
      publicKey: proof.publicKey,
      signature: proof.signature
    }), proofWire);
    assert.equal(server.strictVerifyMessagingDeviceEd25519V1(
      encoder.encode(preimage),
      proof.publicKey,
      proof.signature
    ), true);
  }
});

test("account switching during an await fails before persistence", async () => {
  const idb = idbHarness();
  const subjectState = { value: SUBJECT };
  let release;
  const pendingBinding = new Promise((resolve) => { release = resolve; });
  const { controller } = setup({
    idb,
    subjectState,
    readX25519Binding: () => pendingBinding
  });
  const work = controller.prepare();
  await drain();
  subjectState.value = OTHER_SUBJECT;
  release(binding());
  await assert.rejects(work, unavailable);
  assert.equal(idb.stored(), undefined);
});

test("a stored key cannot be overwritten by another account or exact device", async () => {
  const idb = idbHarness();
  const subjectState = { value: SUBJECT };
  let currentBinding = binding();
  const first = setup({
    idb,
    subjectState,
    readX25519Binding: async () => currentBinding
  });
  const original = await first.controller.prepare();
  subjectState.value = OTHER_SUBJECT;
  currentBinding = binding({
    subject: OTHER_SUBJECT,
    deviceId: OTHER_DEVICE,
    bindingId: OTHER_BINDING_ID,
    publicKey: OTHER_X25519_PUBLIC_KEY
  });
  await assert.rejects(first.controller.prepare(), unavailable);
  assert.equal(idb.stored().subject, SUBJECT);
  assert.equal(idb.stored().deviceId, DEVICE);

  subjectState.value = SUBJECT;
  currentBinding = binding({
    deviceId: OTHER_DEVICE,
    bindingId: OTHER_BINDING_ID,
    publicKey: OTHER_X25519_PUBLIC_KEY
  });
  await assert.rejects(first.controller.prepare(), unavailable);
  assert.equal(idb.stored().ed25519PublicKey, original.ed25519PublicKey);
});

test("proof signing rechecks the session context after WebCrypto awaits", async () => {
  let releaseSign;
  const signGate = new Promise((resolve) => { releaseSign = resolve; });
  let signStarted;
  const started = new Promise((resolve) => { signStarted = resolve; });
  const crypto = trackedCrypto({
    beforeSign: async () => {
      signStarted();
      await signGate;
    }
  });
  const subjectState = { value: SUBJECT };
  const { controller } = setup({ crypto, subjectState });
  const key = await controller.prepare();
  const work = controller.createEnrollmentProofV2(enrollmentWire(key));
  await started;
  subjectState.value = OTHER_SUBJECT;
  releaseSign();
  await assert.rejects(work, unavailable);
});

test("proof signing rejects every local Enrollment V2 identity substitution", async () => {
  const { controller } = setup();
  const key = await controller.prepare();
  const substitutions = [
    { subject: OTHER_SUBJECT },
    { deviceId: OTHER_DEVICE },
    { x25519BindingId: OTHER_BINDING_ID },
    { x25519BindingVersion: 2 },
    { x25519PublicKeyCommitment:
      "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "aa".repeat(32) },
    { ed25519PublicKey: "bb".repeat(32) },
    { profile: PROFILE + ".other" },
    { audience: "https://SOCIAL.example" }
  ];
  for (const replacement of substitutions) {
    await assert.rejects(
      controller.createEnrollmentProofV2(enrollmentWire(key, replacement)),
      unavailable
    );
  }
  await assert.rejects(
    controller.createEnrollmentProofV2(enrollmentWire(key) + "\n"),
    unavailable
  );
});

test("expired bindings, stale enrollment and non-strict IndexedDB durability fail closed", async () => {
  const expiredBinding = binding();
  expiredBinding.acceptedBinding.expiresAt = NOW;
  await assert.rejects(setup({ x25519Binding: expiredBinding }).controller.prepare(),
    unavailable);

  const valid = setup();
  const key = await valid.controller.prepare();
  await assert.rejects(valid.controller.createEnrollmentProofV2(
    enrollmentWire(key, { expiresAt: NOW })
  ), unavailable);

  const weak = setup({ idb: idbHarness({ durability: "default" }) });
  await assert.rejects(weak.controller.prepare(), unavailable);
  assert.equal(weak.idb.stored(), undefined);
});
