import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  createMessagingDevice,
  createMessagingDeviceStore,
  MESSAGING_DEVICE_TIMESTAMP_UNIT
} from "../web/messaging-device-v128c1.mjs";
import {
  canonicalMessagingDeviceAuthorizationProposal
} from "../web/messaging-device-authorization-v1.mjs";
import { renderSecureMessagingAuthenticatedShell } from "../web/secure-messaging-v128.mjs";
import { normalizeMessagingDeviceSnapshot, normalizeMessagingDeviceResult } from "../src/server/ubid-messaging-device-client.mjs";

const subject = "a".repeat(64);
const secondSubject = "b".repeat(64);
const now = 1_788_652_800_000;
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
const metadata = () => ({ bindingId: "3".repeat(64), version: 1, validFrom: now - 100_000, expiresAt: now + 86_400_000 });
const proofId = "hodlxxi-binding-authorization-v1-sha256:" + "8".repeat(64);
const marker = (overrides = {}) => ({
  action: "register", bindingId: metadata().bindingId, proofId,
  requestId: pending().requestId, ...overrides
});
const authorized = () => ({
  ...pending(), state: "ready", acceptedBinding: metadata(),
  authorization: marker(), pendingAuthorization: null, rotation: null
});
const authorizationResult = (proposal, {
  active: isActive = proposal.operation !== "revoke",
  bindingId = metadata().bindingId,
  bindingOperation = proposal.operation,
  bindingVersion = proposal.operation === "register" ? 1 : 2,
  deviceId: resultDeviceId = proposal.deviceId,
  validFrom = now - 100_000,
  expiresAt = now + 86_400_000
} = {}) => ({
  action: proposal.operation,
  active: isActive,
  authorizationExpiresAt: new Date(expiresAt).toISOString().replace(".000Z", "Z"),
  authorizationProofId: proofId,
  authorizationValidFrom: new Date(validFrom).toISOString().replace(".000Z", "Z"),
  bindingId,
  bindingOperation,
  bindingVersion,
  deviceId: resultDeviceId,
  expiresAt: new Date(expiresAt).toISOString().replace(".000Z", "Z"),
  requestId: proposal.requestId,
  schema: "hodlxxi.social_messaging_device_binding_authorization_result.v1",
  validFrom: new Date(validFrom).toISOString().replace(".000Z", "Z"),
  version: 1
});
const publicRetry = (proposal, event = { public: true }) => ({
  intentToken: "public-intent-token",
  proposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
  schema: "hodlxxi.social_messaging_device_binding_authorization_retry.v1",
  signedEvent: event,
  subject,
  version: 1
});
const active = (record = pending()) => ({
  deviceId: record.deviceId, publicKey: record.publicKey, algorithm: "x25519-v1",
  ...metadata(), snapshotId, revoked: false
});
const snapshot = (devices = []) => ({
  schema: prefix + "snapshot.v1", version: 1, source: "hodlxxi-ubid", snapshotId,
  complete: true, issuedAt: now - 10_000, expiresAt: now + 60_000, activeDevices: devices
});
const result = (record = pending()) => ({
  schema: prefix + "result.v1", version: 1, operation: "register",
  device: {
    deviceId: record.deviceId, publicKey: record.publicKey, algorithm: "x25519-v1", ...metadata(),
    validFrom: new Date(now - 100_000).toISOString().replace(".000Z", "Z"),
    expiresAt: new Date(now + 86_400_000).toISOString().replace(".000Z", "Z")
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
        return (typeof options.raw === "function" ? options.raw(pairs.length) : options.raw) ??
          publicBytes.slice().buffer;
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

test("enabled authorization composes register only after explicit setup and blocks the legacy POST", async () => {
  let authorized = false;
  const h = harness({
    snapshot: (record) => snapshot(authorized && record ? [active(record)] : [])
  });
  const calls = [];
  const signer = Object.freeze({ signEventForSubject() {} });
  const authorizedResult = {
    action: "register",
    active: true,
    authorizationExpiresAt: new Date(now + 86_400_000).toISOString().replace(".000Z", "Z"),
    authorizationProofId: proofId,
    authorizationValidFrom: new Date(now - 100_000).toISOString().replace(".000Z", "Z"),
    bindingId: "3".repeat(64),
    bindingOperation: "register",
    bindingVersion: 1,
    deviceId: "01".repeat(32),
    expiresAt: new Date(now + 86_400_000).toISOString().replace(".000Z", "Z"),
    requestId: "02".repeat(32),
    schema: "hodlxxi.social_messaging_device_binding_authorization_result.v1",
    validFrom: new Date(now - 100_000).toISOString().replace(".000Z", "Z"),
    version: 1
  };
  const controller = h.make({
    authorizationEnabled: true,
    authorizationSigner: signer,
    async authorizeBinding(input, dependencies) {
      calls.push([input, dependencies]);
      await dependencies.persistPending({
        intentToken: "public-token",
        proposal: canonicalMessagingDeviceAuthorizationProposal(input.proposal),
        schema: "hodlxxi.social_messaging_device_binding_authorization_retry.v1",
        signedEvent: { public: true },
        subject,
        version: 1
      });
      assert.equal(h.stored().state, "pending-register");
      assert.equal(h.stored().pendingAuthorization.intentToken, "public-token");
      authorized = true;
      return authorizedResult;
    }
  });
  assert.equal(calls.length, 0);
  assert.equal((await controller.reconcile()).state, "not-configured");
  assert.equal(calls.length, 0);
  assert.equal((await controller.setup()).state, "ready");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0][0], {
    subject,
    proposal: {
      deviceId: "01".repeat(32), expectedBindingId: null, operation: "register",
      publicKey: publicHex, requestId: "02".repeat(32)
    }
  });
  assert.equal(calls[0][1].signer, signer);
  assert.equal(h.posts().length, 0);
  assert.deepEqual(h.stored().authorization, marker());
  assert.equal(h.stored().pendingAuthorization, null);
});

test("legacy binding stays non-ready until an explicit adoption with a new requestId", async () => {
  const legacy = { ...pending(), state: "ready", acceptedBinding: metadata() };
  const predecessorKey = legacy.privateKey;
  const calls = [];
  const h = harness({ record: legacy, snapshot: () => snapshot([active(legacy)]) });
  const controller = h.make({
    authorizationEnabled: true,
    authorizationSigner: { signEventForSubject() {} },
    async authorizeBinding(input, dependencies) {
      calls.push(input);
      assert.equal(input.proposal.operation, "adopt");
      assert.equal(input.proposal.bindingId, metadata().bindingId);
      assert.notEqual(input.proposal.requestId, legacy.requestId);
      await dependencies.persistPending(publicRetry(input.proposal));
      assert.equal(h.stored().state, "pending-adopt");
      assert.equal(h.stored().privateKey, predecessorKey);
      return authorizationResult(input.proposal, {
        bindingId: metadata().bindingId,
        bindingOperation: "register",
        bindingVersion: 1,
        deviceId: legacy.deviceId
      });
    }
  });
  assert.equal((await controller.reconcile()).state, "authorization-required");
  assert.equal(calls.length, 0);
  assert.equal((await controller.adopt()).state, "ready");
  assert.equal(calls.length, 1);
  assert.equal(h.stored().privateKey, predecessorKey);
  assert.deepEqual(h.stored().authorization, marker({
    action: "adopt", requestId: calls[0].proposal.requestId
  }));
  assert.equal(h.posts().length, 0);
});

test("explicit rotate retains predecessor until accepted snapshot then promotes replacement", async () => {
  const record = authorized();
  const predecessorKey = record.privateKey;
  const replacementBytes = Uint8Array.from({ length: 32 }, (_, index) => 64 + index);
  const replacementPublicKey = Buffer.from(replacementBytes).toString("hex");
  const replacementBindingId = "4".repeat(64);
  let rotated = false;
  let replacementKey;
  const h = harness({
    record,
    raw: () => replacementBytes.slice().buffer,
    snapshot: () => snapshot(rotated ? [{
      ...active(record),
      bindingId: replacementBindingId,
      version: 2,
      publicKey: replacementPublicKey
    }] : [active(record)])
  });
  const controller = h.make({
    authorizationEnabled: true,
    authorizationSigner: { signEventForSubject() {} },
    async authorizeBinding(input, dependencies) {
      assert.deepEqual(input.proposal, {
        deviceId: record.deviceId,
        expectedBindingId: metadata().bindingId,
        operation: "rotate",
        publicKey: replacementPublicKey,
        requestId: h.stored().rotation.requestId
      });
      replacementKey = h.stored().rotation.privateKey;
      assert.equal(h.stored().privateKey, predecessorKey);
      await dependencies.persistPending(publicRetry(input.proposal));
      assert.equal(h.stored().privateKey, predecessorKey);
      assert.equal(h.stored().rotation.privateKey, replacementKey);
      rotated = true;
      return authorizationResult(input.proposal, {
        bindingId: replacementBindingId,
        bindingOperation: "rotate",
        bindingVersion: 2
      });
    }
  });
  assert.equal((await controller.reconcile()).state, "ready");
  assert.equal((await controller.rotate()).state, "ready");
  assert.equal(h.stored().privateKey, replacementKey);
  assert.equal(h.stored().publicKey, replacementPublicKey);
  assert.equal(h.stored().rotation, null);
  assert.equal(h.stored().authorization.action, "rotate");
  assert.equal(h.stored().authorization.bindingId, replacementBindingId);
});

for (const failure of ["intent", "NIP-07 rejection", "cancellation", "persistence"]) {
  test(`rotate ${failure} before signed retry persistence retains one exact recoverable replacement`, async () => {
    const predecessor = authorized();
    const replacementBytes = Uint8Array.from({ length: 32 }, (_, index) => 32 + index);
    const replacementPublicKey = Buffer.from(replacementBytes).toString("hex");
    const replacementBindingId = "4".repeat(64);
    let attempts = 0, rotated = false, failPersist = failure === "persistence";
    let controller, retainedProposal, retainedRotation;
    const h = harness({
      record: predecessor,
      raw: replacementBytes.slice().buffer,
      update(candidate) {
        if (failPersist && candidate.pendingAuthorization !== null) {
          failPersist = false;
          throw new Error("durable retry write failed");
        }
      },
      snapshot: () => snapshot(rotated ? [{
        ...active(predecessor), bindingId: replacementBindingId, version: 2,
        publicKey: replacementPublicKey
      }] : [active(predecessor)])
    });
    const dependencies = {
      authorizationEnabled: true,
      authorizationSigner: {
        async signEventForSubject() { throw new Error("user rejected"); }
      },
      async authorizeBinding(input, authorizationDependencies) {
        attempts += 1;
        if (attempts === 1) {
          retainedProposal = structuredClone(input.proposal);
          retainedRotation = h.stored().rotation;
          if (failure === "NIP-07 rejection") {
            await authorizationDependencies.signer.signEventForSubject();
          }
          if (failure === "cancellation") controller.cancel();
          if (failure === "persistence") {
            await authorizationDependencies.persistPending(publicRetry(input.proposal));
          }
          throw new Error(`${failure} unavailable`);
        }
        assert.deepEqual(input.proposal, retainedProposal);
        assert.equal(h.stored().rotation.privateKey, retainedRotation.privateKey);
        assert.equal(h.stored().rotation.publicKey, retainedRotation.publicKey);
        assert.equal(h.stored().rotation.requestId, retainedRotation.requestId);
        await authorizationDependencies.persistPending(publicRetry(input.proposal));
        rotated = true;
        return authorizationResult(input.proposal, {
          bindingId: replacementBindingId,
          bindingOperation: "rotate",
          bindingVersion: 2
        });
      }
    };
    controller = h.make(dependencies);
    assert.equal((await controller.reconcile()).state, "ready");
    const failed = await controller.rotate();
    assert.equal(failed.state, failure === "cancellation" ? "unavailable" : "pending-rotate");
    assert.equal(h.stored().state, "pending-rotate");
    assert.equal(h.stored().pendingAuthorization, null);
    assert.equal(h.stored().rotation, retainedRotation);
    assert.equal(h.stored().pendingProposal,
      canonicalMessagingDeviceAuthorizationProposal(retainedProposal));
    const callsBeforeReconcile = attempts;
    const reloaded = h.make(dependencies);
    assert.equal((await reloaded.reconcile()).state, "pending-rotate");
    assert.equal(attempts, callsBeforeReconcile, "reconcile must not invoke authorization or signer");
    assert.equal((await reloaded.retry()).state, "ready");
    assert.equal(attempts, callsBeforeReconcile + 1);
    assert.equal(h.pairs.length, 1);
    assert.equal(h.stored().privateKey, retainedRotation.privateKey);
    assert.equal(h.stored().publicKey, retainedRotation.publicKey);
    assert.equal(h.stored().requestId, retainedRotation.requestId);
  });
}

test("explicit revoke retains local key until acceptance and becomes truthfully revoked", async () => {
  const record = authorized();
  const predecessorKey = record.privateKey;
  let revoked = false;
  const calls = [];
  const h = harness({
    record,
    snapshot: () => snapshot(revoked ? [] : [active(record)])
  });
  const controller = h.make({
    authorizationEnabled: true,
    authorizationSigner: { signEventForSubject() {} },
    async authorizeBinding(input, dependencies) {
      calls.push(input);
      assert.equal(input.proposal.operation, "revoke");
      assert.equal(input.proposal.expectedBindingId, metadata().bindingId);
      assert.equal(input.proposal.publicKey, null);
      await dependencies.persistPending(publicRetry(input.proposal));
      assert.equal(h.stored().state, "pending-revoke");
      assert.equal(h.stored().privateKey, predecessorKey);
      revoked = true;
      return authorizationResult(input.proposal, {
        active: false,
        bindingId: "5".repeat(64),
        bindingOperation: "revoke",
        bindingVersion: 2
      });
    }
  });
  assert.equal((await controller.reconcile()).state, "ready");
  assert.equal((await controller.revoke()).state, "revoked");
  assert.equal(calls.length, 1);
  assert.equal(h.stored().privateKey, predecessorKey);
  assert.equal(h.stored().state, "revoked");
  assert.equal(h.stored().acceptedBinding.bindingId, metadata().bindingId);
  assert.equal(h.stored().authorization.action, "revoke");
  assert.equal(h.stored().authorization.bindingId, "5".repeat(64));
});

test("authorization retry is durable, reconcile is signer-free, and explicit retry resubmits without a second signature", async () => {
  let attempts = 0;
  let signed = 0;
  let registered = false;
  let retainedRetry;
  const h = harness({ snapshot: (record) => snapshot(registered && record ? [active(record)] : []) });
  const make = () => h.make({
    authorizationEnabled: true,
    authorizationSigner: { signEventForSubject() { signed += 1; } },
    async parseAuthorizationRetry(value, { proposal }) {
      assert.equal(value, retainedRetry);
      return {
        action: "register", bindingId: metadata().bindingId,
        expiresAt: Math.floor(now / 1000) + 300,
        proofId, requestId: proposal.requestId
      };
    },
    async authorizeBinding(input, dependencies) {
      attempts += 1;
      if (!input.pendingAuthorization) {
        signed += 1;
        retainedRetry = publicRetry(input.proposal, { exact: "signed-event" });
        await dependencies.persistPending(retainedRetry);
        assert.equal(h.stored().pendingAuthorization, retainedRetry);
        throw new Error("lost before response");
      }
      assert.equal(input.pendingAuthorization, retainedRetry);
      registered = true;
      return authorizationResult(input.proposal);
    }
  });
  assert.equal((await make().setup()).state, "pending-register");
  assert.equal(signed, 1);
  const callsBeforeRetry = h.calls.length;
  assert.equal((await make().reconcile()).state, "pending-register");
  assert.equal(signed, 1);
  assert.equal(attempts, 1);
  assert.equal((await make().retry()).state, "ready");
  assert.equal(signed, 1);
  assert.equal(attempts, 2);
  assert.equal(h.calls.slice(callsBeforeRetry).find(([url, init]) =>
    url === route && init.method === "GET")[0], route);
  assert.equal(h.stored().pendingAuthorization, null);
});

test("lost authorization response finalizes from snapshot without signer or resubmission", async () => {
  let submissions = 0;
  let registered = false;
  let retainedRetry;
  const h = harness({ snapshot: (record) => snapshot(registered && record ? [active(record)] : []) });
  const make = () => h.make({
    authorizationEnabled: true,
    authorizationSigner: { signEventForSubject() { throw new Error("not directly used"); } },
    async parseAuthorizationRetry(value, { proposal }) {
      assert.equal(value, retainedRetry);
      return {
        action: "register", bindingId: metadata().bindingId,
        expiresAt: Math.floor(now / 1000) + 300,
        proofId, requestId: proposal.requestId
      };
    },
    async authorizeBinding(input, dependencies) {
      submissions += 1;
      retainedRetry = publicRetry(input.proposal, { exact: "signed-event" });
      await dependencies.persistPending(retainedRetry);
      registered = true;
      throw new Error("response lost");
    }
  });
  assert.equal((await make().setup()).state, "pending-register");
  assert.equal(submissions, 1);
  assert.equal((await make().reconcile()).state, "ready");
  assert.equal(submissions, 1);
  assert.deepEqual(h.stored().authorization, marker());
});

test("expired or tampered pending authorization never signs or submits during reconcile", async () => {
  const proposal = {
    deviceId: pending().deviceId, expectedBindingId: null, operation: "register",
    publicKey: pending().publicKey, requestId: pending().requestId
  };
  for (const tampered of [false, true]) {
    let submissions = 0;
    const record = {
      ...pending(), authorization: null,
      pendingAuthorization: publicRetry(proposal), rotation: null
    };
    const h = harness({ record });
    const controller = h.make({
      authorizationEnabled: true,
      authorizationSigner: { signEventForSubject() { throw new Error("must not sign"); } },
      async parseAuthorizationRetry() {
        if (tampered) throw new Error("tampered local retry");
        return {
          action: "register", bindingId: metadata().bindingId,
          expiresAt: Math.floor(now / 1000) - 1,
          proofId, requestId: proposal.requestId
        };
      },
      async authorizeBinding() { submissions += 1; throw new Error("must not submit"); }
    });
    assert.equal((await controller.reconcile()).state,
      tampered ? "unavailable" : "pending-register");
    assert.equal(submissions, 0);
    assert.notEqual(h.stored().pendingAuthorization, null);
  }
});

for (const operation of ["register", "adopt", "rotate", "revoke"]) {
  for (const freshness of ["fresh", "expired"]) {
    test(`${freshness} pending ${operation} is signer-free on reconcile and recoverable by explicit retry`, async () => {
      const replacementPublicKey = "d".repeat(64);
      const operationRequestId = operation === "register"
        ? pending().requestId : operation === "rotate" ? "6".repeat(64) : "7".repeat(64);
      const proposal = operation === "adopt" ? {
        bindingId: metadata().bindingId,
        operation,
        requestId: operationRequestId
      } : {
        deviceId: pending().deviceId,
        expectedBindingId: operation === "register" ? null : metadata().bindingId,
        operation,
        publicKey: operation === "rotate" ? replacementPublicKey
          : operation === "revoke" ? null : pending().publicKey,
        requestId: operationRequestId
      };
      const retainedRetry = publicRetry(proposal, { exact: `${freshness}-${operation}` });
      const base = operation === "register" ? {
        ...pending(), authorization: null, rotation: null
      } : {
        ...authorized(),
        ...(operation === "adopt" ? { authorization: null } : {})
      };
      const record = {
        ...base,
        state: operation === "adopt" ? "pending-adopt" : `pending-${operation}`,
        pendingAuthorization: retainedRetry,
        pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
        rotation: operation === "rotate" ? {
          privateKey: new TestCryptoKey("private"),
          publicKey: replacementPublicKey,
          requestId: operationRequestId
        } : null
      };
      let completed = false, submissions = 0, signerCalls = 0;
      const authorizationOrder = [];
      const h = harness({
        record,
        snapshot: () => {
          authorizationOrder.push("snapshot");
          if (!completed) return snapshot(operation === "register" ? [] : [active(record)]);
          if (operation === "revoke") return snapshot([]);
          if (operation === "rotate") return snapshot([{
            ...active(record), bindingId: "4".repeat(64), version: 2,
            publicKey: replacementPublicKey
          }]);
          return snapshot([active(record)]);
        }
      });
      const signer = { signEventForSubject() { signerCalls += 1; } };
      const controller = h.make({
        authorizationEnabled: true,
        authorizationSigner: signer,
        async parseAuthorizationRetry(value, { proposal: checkedProposal }) {
          assert.equal(value, retainedRetry);
          assert.deepEqual(checkedProposal, proposal);
          return {
            action: operation,
            bindingId: operation === "rotate" ? "4".repeat(64)
              : operation === "revoke" ? "5".repeat(64) : metadata().bindingId,
            expiresAt: Math.floor(now / 1000) + (freshness === "fresh" ? 300 : -1),
            proofId,
            requestId: operationRequestId
          };
        },
        async authorizeBinding(input, authorizationDependencies) {
          authorizationOrder.push("submit");
          submissions += 1;
          assert.deepEqual(input.proposal, proposal);
          if (freshness === "fresh") {
            assert.equal(input.pendingAuthorization, retainedRetry);
            assert.equal(input.expiredPendingAuthorization, undefined);
            assert.equal(authorizationDependencies.signer, undefined);
          } else {
            assert.equal(input.pendingAuthorization, undefined);
            assert.equal(input.expiredPendingAuthorization, retainedRetry);
            assert.equal(authorizationDependencies.signer, undefined);
          }
          completed = true;
          if (operation === "adopt") return authorizationResult(proposal, {
            bindingId: metadata().bindingId,
            bindingOperation: "register",
            bindingVersion: 1,
            deviceId: record.deviceId
          });
          if (operation === "rotate") return authorizationResult(proposal, {
            bindingId: "4".repeat(64), bindingOperation: "rotate", bindingVersion: 2
          });
          if (operation === "revoke") return authorizationResult(proposal, {
            active: false, bindingId: "5".repeat(64),
            bindingOperation: "revoke", bindingVersion: 2
          });
          return authorizationResult(proposal);
        }
      });
      assert.equal((await controller.reconcile()).state, record.state);
      assert.equal(submissions, 0);
      assert.equal(signerCalls, 0);
      assert.equal((await controller.retry()).state,
        operation === "revoke" ? "revoked" : "ready");
      assert.equal(submissions, 1);
      assert.equal(signerCalls, 0);
      assert.deepEqual(authorizationOrder, ["snapshot", "snapshot", "submit", "snapshot"]);
      assert.equal(h.stored().pendingAuthorization, null);
      assert.equal(h.stored().pendingProposal, null);
      if (operation === "rotate") {
        assert.equal(h.stored().privateKey, record.rotation.privateKey);
        assert.equal(h.stored().publicKey, replacementPublicKey);
      }
    });
  }
}

for (const operation of ["register", "adopt", "rotate", "revoke"]) {
  for (const failure of [
    "real BFF 503", "upstream timeout/socket failure", "response loss",
    "malformed response", "cancellation"
  ]) {
    test(`${failure} retains expired exact ${operation} without intent or signer`, async () => {
      const replacementPublicKey = "d".repeat(64);
      const operationRequestId = operation === "register"
        ? pending().requestId : operation === "rotate" ? "6".repeat(64) : "7".repeat(64);
      const proposal = operation === "adopt" ? {
        bindingId: metadata().bindingId, operation, requestId: operationRequestId
      } : {
        deviceId: pending().deviceId,
        expectedBindingId: operation === "register" ? null : metadata().bindingId,
        operation,
        publicKey: operation === "rotate" ? replacementPublicKey
          : operation === "revoke" ? null : pending().publicKey,
        requestId: operationRequestId
      };
      const retainedRetry = publicRetry(proposal, {
        intentToken: `${failure}-${operation}`,
        signedEvent: `${failure}-${operation}`
      });
      const base = operation === "register" ? {
        ...pending(), authorization: null, rotation: null
      } : {
        ...authorized(), ...(operation === "adopt" ? { authorization: null } : {})
      };
      const record = {
        ...base,
        state: operation === "adopt" ? "pending-adopt" : `pending-${operation}`,
        pendingAuthorization: retainedRetry,
        pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
        rotation: operation === "rotate" ? {
          privateKey: new TestCryptoKey("private"),
          publicKey: replacementPublicKey,
          requestId: operationRequestId
        } : null
      };
      const retainedBefore = structuredClone(retainedRetry);
      let snapshots = 0, exactSubmissions = 0, intentRequests = 0;
      let nip07Calls = 0, nip46Calls = 0;
      const cancellationEntered = failure === "cancellation" ? deferred() : null;
      const h = harness({
        record,
        snapshot: () => {
          snapshots += 1;
          return snapshot(operation === "register" ? [] : [active(record)]);
        }
      });
      const signer = {};
      Object.defineProperty(signer, "signEventForSubject", {
        get() {
          nip07Calls += 1;
          nip46Calls += 1;
          throw new Error("must not access either signer adapter");
        }
      });
      const controller = h.make({
        authorizationEnabled: true,
        authorizationSigner: signer,
        async parseAuthorizationRetry(value, { proposal: checkedProposal }, options) {
          assert.equal(value, retainedRetry);
          assert.deepEqual(checkedProposal, proposal);
          assert.equal(options.allowExpiredExactReplay, true);
          return {
            action: operation,
            bindingId: operation === "rotate" ? "4".repeat(64)
              : operation === "revoke" ? "5".repeat(64) : metadata().bindingId,
            expiresAt: Math.floor(now / 1000) - 1,
            proofId,
            requestId: operationRequestId
          };
        },
        async authorizeBinding(input, dependencies) {
          if (input.pendingAuthorization === undefined &&
              input.expiredPendingAuthorization === undefined) intentRequests += 1;
          assert.equal(input.expiredPendingAuthorization, retainedRetry);
          assert.equal(input.pendingAuthorization, undefined);
          assert.equal(dependencies.signer, undefined);
          exactSubmissions += 1;
          if (cancellationEntered) {
            cancellationEntered.resolve();
            return new Promise((resolve, reject) => {
              dependencies.signal.addEventListener("abort", () => reject(new Error("cancelled")));
            });
          }
          throw new Error("messaging device authorization unavailable");
        }
      });
      const work = controller.retry();
      if (cancellationEntered) {
        await cancellationEntered.promise;
        controller.cancel();
      }
      assert.equal((await work).state, cancellationEntered ? "unavailable" : record.state);
      assert.equal(snapshots, 1);
      assert.equal(exactSubmissions, 1);
      assert.equal(intentRequests, 0);
      assert.equal(nip07Calls, 0);
      assert.equal(nip46Calls, 0);
      assert.equal(h.stored().pendingAuthorization, retainedRetry);
      assert.deepEqual(h.stored().pendingAuthorization, retainedBefore);
      assert.equal(h.stored().pendingProposal,
        canonicalMessagingDeviceAuthorizationProposal(proposal));
    });
  }
}

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

test("verified UBID millisecond snapshot contract is compared to a millisecond clock", async () => {
  assert.equal(MESSAGING_DEVICE_TIMESTAMP_UNIT, "unix-milliseconds");
  const record = pending();
  const server = snapshot([active(record)]);
  assert.equal(server.issuedAt, 1_788_652_790_000);
  assert.equal(server.expiresAt, 1_788_652_860_000);
  const h = harness({ record, snapshot: () => server });
  assert.equal((await h.controller.reconcile()).state, "ready");
  assert.deepEqual(h.stored().acceptedBinding, {
    bindingId: "3".repeat(64),
    version: 1,
    validFrom: 1_788_652_700_000,
    expiresAt: 1_788_739_200_000
  });
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
  ["pending-register", "Secure device setup can continue"],
  ["authorization-required", "Authorize this existing device"],
  ["pending-adopt", "Device authorization can continue"],
  ["pending-rotate", "Device-key rotation can continue"],
  ["pending-revoke", "Device revocation can continue"],
  ["ready", "This device is ready for end-to-end encryption"],
  ["revoked", "This device is revoked"],
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
  assert.equal(html.includes("data-secure-v128-adopt-device"), state === "authorization-required");
  assert.equal(html.includes("data-secure-v128-rotate-device"), state === "ready");
  assert.equal(html.includes("data-secure-v128-revoke-device"), state === "ready");
  assert.equal(html.includes("data-secure-v128-retry-device"), [
    "pending-register", "pending-adopt", "pending-rotate", "pending-revoke"
  ].includes(state));
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
  assert.match(source, /MESSAGING_DEVICE_TIMESTAMP_UNIT = "unix-milliseconds"/);
  assert.match(source, /now = Date\.now/);
  assert.doesNotMatch(source, /timestamp[^\n]*(?:magnitude|length)/i);
  assert.match(source, /store\.add\(localRecord\(next, next\.subject, CryptoKeyImpl\), "current"\)/);
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
  const NativeCryptoKey = pair.privateKey.constructor;
  assert.equal(typeof NativeCryptoKey, "function");
  assert.equal(retained.privateKey instanceof NativeCryptoKey, true);
  assert.equal(retained.privateKey.extractable, false);
  assert.equal(retained.privateKey.type, "private");
  assert.equal(retained.publicKey, record.publicKey);
});

test("native store abort after successful add prevents registration", async () => {
  const idb = idbHarness({ abortWrites: true });
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const NativeCryptoKey = pair.privateKey.constructor;
  const h = harness({ dependencies: { store: createMessagingDeviceStore(idb.factory),
    cryptoImpl: webcrypto, CryptoKeyImpl: NativeCryptoKey } });
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
  await assert.rejects(store.update(other, record));
  assert.equal((await store.read()).subject, subject);
});

test("native store updates accepted metadata while retaining the cloned private key", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const record = { ...pending(), privateKey: pair.privateKey };
  await store.create(record);
  await store.update({ ...record, state: "ready", acceptedBinding: metadata(), privateKey: null }, record);
  const ready = await store.read();
  assert.equal(ready.state, "ready");
  assert.equal(ready.privateKey.extractable, false);
  assert.deepEqual(ready.acceptedBinding, metadata());
  await assert.rejects(store.update(
    { ...record, acceptedBinding: { ...metadata(), bindingId: "8".repeat(64) } }, ready
  ));
});

test("native store prevents stale deletion of a persisted rotation predecessor", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const predecessor = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const replacement = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const predecessorPublicKey = Buffer.from(await webcrypto.subtle.exportKey("raw", predecessor.publicKey)).toString("hex");
  const replacementPublicKey = Buffer.from(await webcrypto.subtle.exportKey("raw", replacement.publicKey)).toString("hex");
  const record = {
    ...authorized(),
    privateKey: predecessor.privateKey,
    publicKey: predecessorPublicKey
  };
  await store.create(record);
  const rotation = {
    privateKey: replacement.privateKey,
    publicKey: replacementPublicKey,
    requestId: "6".repeat(64)
  };
  await store.update({ ...record, rotation, state: "pending-rotate" }, record);
  const pendingRotation = await store.read();
  assert.equal(pendingRotation.privateKey.extractable, false);
  assert.equal(pendingRotation.publicKey, predecessorPublicKey);
  assert.equal(pendingRotation.rotation.privateKey.extractable, false);
  assert.equal(pendingRotation.rotation.publicKey, replacementPublicKey);
  await assert.rejects(store.update({ ...record, rotation: null, state: "ready" }, pendingRotation));
  assert.equal((await store.read()).rotation.publicKey, replacementPublicKey);

  const rotatedMetadata = {
    ...metadata(), bindingId: "4".repeat(64), version: 2
  };
  await store.update({
    ...pendingRotation,
    privateKey: replacement.privateKey,
    publicKey: replacementPublicKey,
    requestId: rotation.requestId,
    acceptedBinding: rotatedMetadata,
    authorization: marker({
      action: "rotate", bindingId: rotatedMetadata.bindingId,
      requestId: rotation.requestId
    }),
    pendingAuthorization: null,
    pendingProposal: null,
    rotation: null,
    state: "ready"
  }, pendingRotation);
  const ready = await store.read();
  assert.equal(ready.privateKey.extractable, false);
  assert.equal(ready.publicKey, replacementPublicKey);
  assert.deepEqual(ready.acceptedBinding, rotatedMetadata);
  assert.equal(ready.rotation, null);
});

test("native store CAS blocks stale tabs from replacing a different rotation and retains the winning private key", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const predecessor = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const firstReplacement = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const staleReplacement = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const peer = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const predecessorPublicKey = Buffer.from(
    await webcrypto.subtle.exportKey("raw", predecessor.publicKey)
  ).toString("hex");
  const firstPublicKey = Buffer.from(
    await webcrypto.subtle.exportKey("raw", firstReplacement.publicKey)
  ).toString("hex");
  const stalePublicKey = Buffer.from(
    await webcrypto.subtle.exportKey("raw", staleReplacement.publicKey)
  ).toString("hex");
  const record = {
    ...authorized(), privateKey: predecessor.privateKey, publicKey: predecessorPublicKey
  };
  await store.create(record);
  const staleBase = await store.read();
  const firstRotation = {
    privateKey: firstReplacement.privateKey,
    publicKey: firstPublicKey,
    requestId: "6".repeat(64)
  };
  const staleRotation = {
    privateKey: staleReplacement.privateKey,
    publicKey: stalePublicKey,
    requestId: "7".repeat(64)
  };
  const rotationCandidate = (rotation) => {
    const proposal = {
      deviceId: record.deviceId,
      expectedBindingId: metadata().bindingId,
      operation: "rotate",
      publicKey: rotation.publicKey,
      requestId: rotation.requestId
    };
    return {
      ...staleBase,
      pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
      rotation,
      state: "pending-rotate"
    };
  };
  await store.update(rotationCandidate(firstRotation), staleBase);
  await assert.rejects(store.update(rotationCandidate(staleRotation), staleBase),
    /device store unavailable/);
  const winning = await store.read();
  assert.equal(winning.rotation.publicKey, firstPublicKey);
  assert.equal(winning.rotation.requestId, firstRotation.requestId);

  await assert.rejects(store.update({ ...winning, state: "ready" }, winning),
    /device store unavailable/);
  assert.equal((await store.read()).state, "pending-rotate");

  const rotatedMetadata = { ...metadata(), bindingId: "4".repeat(64), version: 2 };
  await store.update({
    ...winning,
    privateKey: staleReplacement.privateKey,
    publicKey: firstPublicKey,
    requestId: firstRotation.requestId,
    acceptedBinding: rotatedMetadata,
    authorization: marker({
      action: "rotate", bindingId: rotatedMetadata.bindingId,
      requestId: firstRotation.requestId
    }),
    pendingAuthorization: null,
    pendingProposal: null,
    rotation: null,
    state: "ready"
  }, winning);
  const accepted = await store.read();
  const retainedSecret = Buffer.from(await webcrypto.subtle.deriveBits(
    { name: "X25519", public: peer.publicKey }, accepted.privateKey, 256
  ));
  const winningSecret = Buffer.from(await webcrypto.subtle.deriveBits(
    { name: "X25519", public: peer.publicKey }, firstReplacement.privateKey, 256
  ));
  const staleSecret = Buffer.from(await webcrypto.subtle.deriveBits(
    { name: "X25519", public: peer.publicKey }, staleReplacement.privateKey, 256
  ));
  assert.equal(accepted.publicKey, firstPublicKey);
  assert.deepEqual(retainedSecret, winningSecret);
  assert.notDeepEqual(retainedSecret, staleSecret);
});

test("native store CAS blocks stale retry overwrite and stale retry clearing", async () => {
  const idb = idbHarness(), store = createMessagingDeviceStore(idb.factory);
  const pair = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const proposal = {
    deviceId: pending().deviceId,
    expectedBindingId: null,
    operation: "register",
    publicKey: pending().publicKey,
    requestId: pending().requestId
  };
  const record = {
    ...pending(),
    privateKey: pair.privateKey,
    authorization: null,
    pendingAuthorization: null,
    pendingProposal: canonicalMessagingDeviceAuthorizationProposal(proposal),
    rotation: null
  };
  await store.create(record);
  const staleBase = await store.read();
  const firstRetry = publicRetry(proposal, { winner: true });
  const staleRetry = publicRetry(proposal, { stale: true });
  await store.update({ ...staleBase, pendingAuthorization: firstRetry }, staleBase);
  await assert.rejects(
    store.update({ ...staleBase, pendingAuthorization: staleRetry }, staleBase),
    /device store unavailable/
  );
  await assert.rejects(store.update({
    ...staleBase,
    acceptedBinding: metadata(),
    pendingAuthorization: null,
    pendingProposal: null,
    state: "ready"
  }, staleBase), /device store unavailable/);
  const retained = await store.read();
  assert.deepEqual(retained.pendingAuthorization, firstRetry);
  assert.equal(retained.state, "pending-register");
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
