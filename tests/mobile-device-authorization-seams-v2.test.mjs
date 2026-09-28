import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createDesktopPreEnrollmentApprovalV2,
  preEnrollmentComparisonCode,
  prepareProvisionalMessagingDeviceV2
} from "../web/mobile-device-authorization-seams-v2.mjs";

const vector = JSON.parse(await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
  import.meta.url
))).vector;
const pre = JSON.parse(vector.preEnrollmentWire);
const outer = JSON.parse(vector.authorizationWire);
const event = JSON.parse(vector.approvalEventWire);
const proposal = Object.freeze({
  deviceId: pre.deviceId,
  expectedBindingId: null,
  operation: "register",
  publicKey: "09" + "00".repeat(31),
  requestId: pre.requestId
});
const pendingProposal = JSON.stringify(proposal);
const failure = {
  name: "TypeError",
  message: "mobile device authorization v2 seam unavailable"
};

function pending() {
  return {
    deviceId: pre.deviceId,
    pendingProposal,
    publicKey: proposal.publicKey,
    requestId: pre.requestId,
    state: "pending-register",
    subject: pre.subject
  };
}

function fullContextState() {
  return {
    access: "full",
    authorizationDigest: vector.authorizationDigest,
    pairingId: pre.pairingId,
    revision: "cc".repeat(32),
    subject: pre.subject
  };
}

function durableBoundary({ failPersistence = false } = {}) {
  let signingClaim;
  let signedAttempt;
  let claimCalls = 0;
  let persistCalls = 0;
  let readCalls = 0;
  return {
    async readSignedAttempt() {
      readCalls += 1;
      return signedAttempt;
    },
    async claimSigningAttempt() {
      claimCalls += 1;
      if (signedAttempt !== undefined) {
        return { status: "signed", signedAttemptWire: signedAttempt };
      }
      if (signingClaim !== undefined) {
        return { status: "ambiguous", signingClaimWire: signingClaim };
      }
      signingClaim = "durable-signing-claim";
      return { status: "claimed", signingClaimWire: signingClaim };
    },
    async persistSignedAttempt(claim, wire) {
      persistCalls += 1;
      assert.equal(claim, signingClaim);
      if (failPersistence) throw new Error("simulated crash before commit");
      if (signedAttempt !== undefined) assert.equal(signedAttempt, wire);
      signedAttempt = wire;
      return wire;
    },
    state: () => ({
      claimCalls, persistCalls, readCalls, signedAttempt, signingClaim
    })
  };
}

function setup({
  boundary = durableBoundary(),
  contextState = fullContextState(),
  getContextImpl,
  nowState = { value: pre.issuedAt },
  nowMs,
  providerFactory,
  readPendingImpl
} = {}) {
  let getPublicKeyCalls = 0;
  let signEventCalls = 0;
  let resolveCalls = 0;
  let signedInput;
  const defaultFactory = () => ({
    async getPublicKey() {
      getPublicKeyCalls += 1;
      return pre.subject;
    },
    async signEvent(unsigned) {
      signEventCalls += 1;
      signedInput = unsigned;
      return event;
    }
  });
  const controller = createDesktopPreEnrollmentApprovalV2({
    enabled: true,
    getContext: getContextImpl ?? (() => ({ ...contextState })),
    readX25519Pending: readPendingImpl ?? (async () => pending()),
    keyBoundary: boundary,
    resolveProvider: () => {
      resolveCalls += 1;
      return (providerFactory ?? defaultFactory)({
        incrementGet() { getPublicKeyCalls += 1; },
        incrementSign() { signEventCalls += 1; },
        setSignedInput(value) { signedInput = value; }
      });
    },
    nowMs: nowMs ?? (() => nowState.value),
    cryptoImpl: webcrypto
  });
  return {
    boundary,
    contextState,
    controller,
    counts: () => ({ getPublicKeyCalls, resolveCalls, signEventCalls }),
    nowState,
    signedInput: () => signedInput
  };
}

function clockAuthorityRace(mutation, contextState) {
  let armed = false;
  let controller;
  let mutationCalls = 0;
  let validReadsBeforeMutation = 0;
  return {
    arm(afterValidReads = 0) {
      assert.equal(armed, false, `${mutation}: race already armed`);
      armed = true;
      validReadsBeforeMutation = afterValidReads;
    },
    attach(value) { controller = value; },
    calls: () => mutationCalls,
    nowMs() {
      if (armed && validReadsBeforeMutation > 0) {
        validReadsBeforeMutation -= 1;
      } else if (armed) {
        armed = false;
        mutationCalls += 1;
        if (mutation === "revision") {
          contextState.revision = "dd".repeat(32);
        } else {
          controller.cancel();
        }
      }
      return pre.issuedAt;
    }
  };
}

function pendingPhaseArm(race, targetCall, afterValidReads = 0) {
  let calls = 0;
  return {
    calls: () => calls,
    async read() {
      calls += 1;
      if (calls === targetCall) race.arm(afterValidReads);
      return pending();
    }
  };
}

const approve = (controller) => controller.approve({
  authorizationWire: vector.authorizationWire,
  comparisonCode: preEnrollmentComparisonCode(vector.authorizationDigest),
  proposal
});

async function assertPublicDenial(operation, label) {
  let error;
  try { await operation(); } catch (caught) { error = caught; }
  assert.equal(error?.constructor, TypeError, label);
  assert.equal(error?.message, failure.message, label);
  assert.equal(String(error), `TypeError: ${failure.message}`, label);
  assert.equal(Object.hasOwn(error, "cause"), false, label);
  assert.equal(Object.hasOwn(error, "context"), false, label);
  assert.deepEqual(Object.keys(error), [], label);
}

test("preparation seam returns only prepared-provisional public material", async () => {
  let calls = 0;
  const result = await prepareProvisionalMessagingDeviceV2({
    enabled: true,
    bindingAuthorizationContent: outer.content,
    keyBoundary: {
      async prepare(content) {
        calls += 1;
        assert.equal(content, outer.content);
        return Object.freeze({
          schema:
            "hodlxxi.social_messaging_device_ed25519_provisional_key_public.v2",
          version: 2,
          state: "prepared-provisional",
          subjectHint: pre.subject,
          deviceId: pre.deviceId,
          requestId: pre.requestId,
          x25519BindingId: pre.x25519BindingId,
          x25519BindingVersion: 1,
          x25519PublicKeyCommitment: pre.x25519PublicKeyCommitment,
          ed25519PublicKey: pre.ed25519PublicKey,
          recordRevision: "dd".repeat(32)
        });
      }
    }
  });
  assert.equal(calls, 1);
  assert.equal(result.state, "prepared-provisional");
  assert.equal(Object.hasOwn(result, "privateKey"), false);
  assert.equal(Object.isFrozen(result), true);
});

test("preparation seam reconstructs a closed scalar DTO and rejects sensitive aliases", async () => {
  const valid = {
    schema:
      "hodlxxi.social_messaging_device_ed25519_provisional_key_public.v2",
    version: 2,
    state: "prepared-provisional",
    subjectHint: pre.subject,
    deviceId: pre.deviceId,
    requestId: pre.requestId,
    x25519BindingId: pre.x25519BindingId,
    x25519BindingVersion: 1,
    x25519PublicKeyCommitment: pre.x25519PublicKeyCommitment,
    ed25519PublicKey: pre.ed25519PublicKey,
    recordRevision: "dd".repeat(32)
  };
  for (const mutate of [
    (value) => ({ ...value, private_key: "secret" }),
    (value) => ({ ...value, seed: "secret" }),
    (value) => ({ ...value, key: "secret" }),
    (value) => Object.assign(value, { unknown: true }),
    (value) => {
      Object.defineProperty(value, Symbol("secret"), { value: true });
      return value;
    },
    (value) => {
      Object.defineProperty(value, "recordRevision", {
        enumerable: true,
        get() { throw new Error("sensitive getter"); }
      });
      return value;
    },
    (value) => ({ ...value, schema: new String(value.schema) }),
    (value) => ({ ...value, version: new Number(value.version) }),
    (value) => ({ ...value, state: new String(value.state) }),
    (value) => ({ ...value, subjectHint: new String(value.subjectHint) }),
    (value) => ({ ...value, deviceId: new String(value.deviceId) }),
    (value) => ({ ...value, requestId: new String(value.requestId) }),
    (value) => ({ ...value, x25519BindingId: new String(value.x25519BindingId) }),
    (value) => ({
      ...value,
      x25519BindingVersion: new Number(value.x25519BindingVersion)
    }),
    (value) => ({
      ...value,
      x25519PublicKeyCommitment:
        new String(value.x25519PublicKeyCommitment)
    }),
    (value) => ({
      ...value,
      ed25519PublicKey: new String(value.ed25519PublicKey)
    }),
    (value) => ({ ...value, recordRevision: new String(value.recordRevision) })
  ]) {
    const injected = mutate({ ...valid });
    await assert.rejects(prepareProvisionalMessagingDeviceV2({
      enabled: true,
      bindingAuthorizationContent: outer.content,
      keyBoundary: { async prepare() { return injected; } }
    }), failure);
  }
  const injected = { ...valid };
  const result = await prepareProvisionalMessagingDeviceV2({
    enabled: true,
    bindingAuthorizationContent: outer.content,
    keyBoundary: { async prepare() { return injected; } }
  });
  assert.notEqual(result, injected);
  assert.deepEqual(result, valid);
  assert.equal(Object.isFrozen(result), true);
});

test("whole-argument proxies and getters fail with only the exact seam error", async () => {
  const secret = "whole-argument-secret";
  const poison = new Proxy({}, {
    ownKeys() { throw new Error(secret); }
  });
  for (const invoke of [
    () => prepareProvisionalMessagingDeviceV2(poison),
    async () => createDesktopPreEnrollmentApprovalV2(poison),
    () => setup().controller.approve(poison)
  ]) {
    let error;
    try { await invoke(); } catch (caught) { error = caught; }
    assert.equal(error?.constructor, TypeError);
    assert.equal(error?.message,
      "mobile device authorization v2 seam unavailable");
    assert.equal(String(error).includes(secret), false);
    assert.equal(Object.hasOwn(error, "cause"), false);
  }
});

test("one NIP-07 call is exact, subject-bound, private and persisted before return", async () => {
  const instance = setup();
  const wire = await approve(instance.controller);
  assert.deepEqual(instance.counts(), {
    getPublicKeyCalls: 1,
    resolveCalls: 1,
    signEventCalls: 1
  });
  assert.deepEqual(instance.signedInput(), {
    content: event.content,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags
  });
  assert.equal(instance.boundary.state().signedAttempt, wire);
  assert.equal(instance.boundary.state().persistCalls, 1);
  assert.equal(wire.includes("privateKey"), false);
  assert.equal(wire.includes("77".repeat(32)), false);
});

test("reload, persistence-before-dispatch and lost response reuse byte-identical evidence", async () => {
  const boundary = durableBoundary();
  const first = setup({ boundary });
  const exact = await approve(first.controller);
  for (let retry = 0; retry < 3; retry += 1) {
    const reopened = setup({
      boundary,
      providerFactory: () => {
        throw new Error("provider must not be reacquired");
      }
    });
    assert.equal(await approve(reopened.controller), exact);
    assert.deepEqual(reopened.counts(), {
      getPublicKeyCalls: 0,
      resolveCalls: 0,
      signEventCalls: 0
    });
  }
  assert.equal(boundary.state().persistCalls, 1);
});

test("signer-return-before-persistence crash retains claim and forbids a second NIP-07 call", async () => {
  const boundary = durableBoundary({ failPersistence: true });
  const first = setup({ boundary });
  await assert.rejects(approve(first.controller), failure);
  assert.equal(first.counts().signEventCalls, 1);
  assert.equal(boundary.state().signingClaim, "durable-signing-claim");
  assert.equal(boundary.state().signedAttempt, undefined);
  const reopened = setup({ boundary });
  await assert.rejects(approve(reopened.controller), failure);
  assert.equal(reopened.counts().signEventCalls, 0);
  assert.equal(reopened.counts().resolveCalls, 0);
});

test("ambiguous signer outcome is durably one-shot and never automatically reacquired", async () => {
  const boundary = durableBoundary();
  const first = setup({
    boundary,
    providerFactory: ({ incrementGet, incrementSign }) => ({
      async getPublicKey() { incrementGet(); return pre.subject; },
      async signEvent() {
        incrementSign();
        throw new Error("wallet outcome unknown");
      }
    })
  });
  await assert.rejects(approve(first.controller), failure);
  assert.equal(first.counts().signEventCalls, 1);
  const reopened = setup({ boundary });
  await assert.rejects(approve(reopened.controller), failure);
  assert.equal(reopened.counts().resolveCalls, 0);
  assert.equal(reopened.counts().signEventCalls, 0);
});

test("wrong signer subject, expiry after awaits and post-return expiry fail closed", async () => {
  const limited = setup({ contextState: {
    access: "limited",
    authorizationDigest: vector.authorizationDigest,
    pairingId: pre.pairingId,
    revision: "cc".repeat(32),
    subject: pre.subject
  } });
  await assert.rejects(approve(limited.controller), failure);
  assert.equal(limited.counts().resolveCalls, 0);

  const wrong = setup({
    providerFactory: ({ incrementGet, incrementSign }) => ({
      async getPublicKey() { incrementGet(); return "11".repeat(32); },
      async signEvent() { incrementSign(); return event; }
    })
  });
  await assert.rejects(approve(wrong.controller), failure);
  assert.equal(wrong.counts().signEventCalls, 0);

  const afterGet = setup({
    providerFactory: ({ incrementGet, incrementSign }) => ({
      async getPublicKey() {
        incrementGet();
        afterGet.nowState.value = pre.expiresAt;
        return pre.subject;
      },
      async signEvent() { incrementSign(); return event; }
    })
  });
  await assert.rejects(approve(afterGet.controller), failure);
  assert.equal(afterGet.counts().signEventCalls, 0);

  const boundary = durableBoundary();
  const afterSign = setup({
    boundary,
    providerFactory: ({ incrementGet, incrementSign }) => ({
      async getPublicKey() { incrementGet(); return pre.subject; },
      async signEvent() {
        incrementSign();
        afterSign.nowState.value = pre.expiresAt;
        return event;
      }
    })
  });
  await assert.rejects(approve(afterSign.controller), failure);
  assert.equal(afterSign.counts().signEventCalls, 1);
  assert.equal(typeof boundary.state().signedAttempt, "string");
  const reopened = setup({ boundary, nowState: afterSign.nowState });
  await assert.rejects(approve(reopened.controller), failure);
  assert.equal(reopened.counts().resolveCalls, 0);
});

test("exact expiry at cached, already-signed and fresh final returns denies", async () => {
  const baselineBoundary = durableBoundary();
  const baseline = setup({ boundary: baselineBoundary });
  const exact = await approve(baseline.controller);
  const runRace = async (name) => {
    let instance;
    let boundary;
    let expectedSignerCalls;
    if (name === "cached") {
      expectedSignerCalls = 0;
      boundary = {
        async readSignedAttempt() {
          queueMicrotask(() => { instance.nowState.value = pre.expiresAt; });
          return exact;
        },
        async claimSigningAttempt() { throw new Error("must not claim"); },
        async persistSignedAttempt() { throw new Error("must not persist"); }
      };
    } else if (name === "already-signed") {
      expectedSignerCalls = 0;
      boundary = {
        async readSignedAttempt() { return undefined; },
        async claimSigningAttempt() {
          queueMicrotask(() => { instance.nowState.value = pre.expiresAt; });
          return { status: "signed", signedAttemptWire: exact };
        },
        async persistSignedAttempt() { throw new Error("must not persist"); }
      };
    } else {
      expectedSignerCalls = 1;
      const inner = durableBoundary();
      boundary = {
        ...inner,
        async persistSignedAttempt(claim, wire) {
          const result = await inner.persistSignedAttempt(claim, wire);
          queueMicrotask(() => { instance.nowState.value = pre.expiresAt; });
          return result;
        }
      };
    }
    instance = setup({ boundary });
    await assert.rejects(approve(instance.controller), failure, name);
    assert.equal(instance.counts().signEventCalls, expectedSignerCalls, name);
  };
  for (const name of ["cached", "already-signed", "fresh"]) {
    await runRace(name);
  }
});

test("clock changes deny before read, claim, resolve and provider descriptors", async () => {
  const phases = [
    "pre-read",
    "pre-claim",
    "pre-resolve",
    "pre-getPublicKey-descriptor",
    "pre-signEvent-descriptor"
  ];
  for (const phase of phases) {
    for (const mutation of ["revision", "cancel"]) {
      const contextState = fullContextState();
      const race = clockAuthorityRace(mutation, contextState);
      const inner = durableBoundary();
      let boundary = inner;
      let pendingArm;
      const descriptorCalls = { getPublicKey: 0, signEvent: 0 };
      if (phase === "pre-claim") {
        boundary = {
          ...inner,
          async readSignedAttempt(wire) {
            const result = await inner.readSignedAttempt(wire);
            race.arm();
            return result;
          }
        };
      } else {
        const targetCall = {
          "pre-read": 3,
          "pre-resolve": 6,
          "pre-getPublicKey-descriptor": 7,
          "pre-signEvent-descriptor": 8
        }[phase];
        pendingArm = pendingPhaseArm(race, targetCall);
      }
      const instance = setup({
        boundary,
        contextState,
        nowMs: race.nowMs,
        readPendingImpl: pendingArm?.read,
        providerFactory: ({ incrementGet, incrementSign }) => new Proxy({
          async getPublicKey() {
            incrementGet();
            return pre.subject;
          },
          async signEvent() {
            incrementSign();
            return event;
          }
        }, {
          getOwnPropertyDescriptor(target, name) {
            if (name === "getPublicKey" || name === "signEvent") {
              descriptorCalls[name] += 1;
            }
            return Reflect.getOwnPropertyDescriptor(target, name);
          }
        })
      });
      race.attach(instance.controller);
      const label = `${phase}/${mutation}`;
      await assertPublicDenial(() => approve(instance.controller), label);
      assert.equal(race.calls(), 1, label);
      assert.equal(inner.state().persistCalls, 0, label);
      assert.equal(inner.state().signedAttempt, undefined, label);
      if (phase === "pre-read") {
        assert.equal(inner.state().readCalls, 0, label);
        assert.equal(inner.state().claimCalls, 0, label);
      } else if (phase === "pre-claim") {
        assert.equal(inner.state().readCalls, 1, label);
        assert.equal(inner.state().claimCalls, 0, label);
        assert.equal(inner.state().signingClaim, undefined, label);
      } else {
        assert.equal(inner.state().readCalls, 1, label);
        assert.equal(inner.state().claimCalls, 1, label);
      }
      if (phase === "pre-resolve") {
        assert.equal(instance.counts().resolveCalls, 0, label);
      }
      if (phase === "pre-getPublicKey-descriptor") {
        assert.equal(descriptorCalls.getPublicKey, 0, label);
        assert.equal(instance.counts().getPublicKeyCalls, 0, label);
      }
      if (phase === "pre-signEvent-descriptor") {
        assert.equal(descriptorCalls.getPublicKey, 1, label);
        assert.equal(instance.counts().getPublicKeyCalls, 1, label);
        assert.equal(descriptorCalls.signEvent, 0, label);
        assert.equal(instance.counts().signEventCalls, 0, label);
      }
    }
  }
});

test("final clock changes deny cached, already-signed and fresh returns", async () => {
  const baselineBoundary = durableBoundary();
  const baseline = setup({ boundary: baselineBoundary });
  const exact = await approve(baseline.controller);
  for (const name of ["cached", "already-signed", "fresh"]) {
    for (const mutation of ["revision", "cancel"]) {
      const contextState = fullContextState();
      const race = clockAuthorityRace(mutation, contextState);
      const targetPendingCall = {
        cached: 5,
        "already-signed": 6,
        fresh: 9
      }[name];
      const pendingArm = pendingPhaseArm(
        race,
        targetPendingCall,
        name === "fresh" ? 0 : 1
      );
      let boundary;
      let freshBoundary;
      if (name === "cached") {
        boundary = {
          async readSignedAttempt() { return exact; },
          async claimSigningAttempt() { throw new Error("must not claim"); },
          async persistSignedAttempt() { throw new Error("must not persist"); }
        };
      } else if (name === "already-signed") {
        boundary = {
          async readSignedAttempt() { return undefined; },
          async claimSigningAttempt() {
            return { status: "signed", signedAttemptWire: exact };
          },
          async persistSignedAttempt() { throw new Error("must not persist"); }
        };
      } else {
        freshBoundary = durableBoundary();
        boundary = {
          ...freshBoundary,
          async persistSignedAttempt(claim, wire) {
            return freshBoundary.persistSignedAttempt(claim, wire);
          }
        };
      }
      const instance = setup({
        boundary,
        contextState,
        nowMs: race.nowMs,
        readPendingImpl: pendingArm.read
      });
      race.attach(instance.controller);
      const label = `${name}/${mutation}`;
      await assertPublicDenial(() => approve(instance.controller), label);
      assert.equal(race.calls(), 1, label);
      assert.equal(pendingArm.calls(), targetPendingCall, label);
      assert.equal(instance.counts().signEventCalls, name === "fresh" ? 1 : 0,
        label);
      if (freshBoundary !== undefined) {
        assert.equal(freshBoundary.state().persistCalls, 1, label);
        assert.equal(typeof freshBoundary.state().signedAttempt, "string", label);
      }
    }
  }
});

test("provider-resolution microtask authority switch occurs before signEvent", async () => {
  const contextState = {
    access: "full",
    authorizationDigest: vector.authorizationDigest,
    pairingId: pre.pairingId,
    revision: "cc".repeat(32),
    subject: pre.subject
  };
  let signEventCalls = 0;
  const controller = createDesktopPreEnrollmentApprovalV2({
    enabled: true,
    getContext: () => ({ ...contextState }),
    readX25519Pending: async () => pending(),
    keyBoundary: durableBoundary(),
    resolveProvider() {
      queueMicrotask(() => { contextState.revision = "dd".repeat(32); });
      return {
        async getPublicKey() { return pre.subject; },
        async signEvent() { signEventCalls += 1; return event; }
      };
    },
    nowMs: () => pre.issuedAt,
    cryptoImpl: webcrypto
  });
  await assert.rejects(approve(controller), failure);
  assert.equal(signEventCalls, 0);
});

test("provider descriptor microtasks deny before getPublicKey or signEvent invocation", async () => {
  for (const method of ["getPublicKey", "signEvent"]) {
    const contextState = {
      access: "full",
      authorizationDigest: vector.authorizationDigest,
      pairingId: pre.pairingId,
      revision: "cc".repeat(32),
      subject: pre.subject
    };
    let queued = false;
    const instance = setup({
      contextState,
      providerFactory: ({ incrementGet, incrementSign }) => new Proxy({
        async getPublicKey() {
          incrementGet();
          return pre.subject;
        },
        async signEvent() {
          incrementSign();
          return event;
        }
      }, {
        getOwnPropertyDescriptor(target, name) {
          if (name === method && !queued) {
            queued = true;
            queueMicrotask(() => {
              contextState.revision = "dd".repeat(32);
            });
          }
          return Reflect.getOwnPropertyDescriptor(target, name);
        }
      })
    });
    let error;
    try { await approve(instance.controller); }
    catch (caught) { error = caught; }
    assert.equal(error?.constructor, TypeError, method);
    assert.equal(error?.message, failure.message, method);
    assert.equal(Object.hasOwn(error, "cause"), false, method);
    assert.deepEqual(instance.counts(), {
      getPublicKeyCalls: method === "signEvent" ? 1 : 0,
      resolveCalls: 1,
      signEventCalls: 0
    }, method);
  }
});

test("descriptor-armed nowMs authority changes deny before provider invocation", async () => {
  for (const method of ["getPublicKey", "signEvent"]) {
    for (const mutation of ["revision", "cancel"]) {
      const contextState = {
        access: "full",
        authorizationDigest: vector.authorizationDigest,
        pairingId: pre.pairingId,
        revision: "cc".repeat(32),
        subject: pre.subject
      };
      const boundary = durableBoundary();
      let armed = false;
      let controller;
      let mutationCalls = 0;
      const instance = setup({
        boundary,
        contextState,
        nowMs() {
          if (armed) {
            armed = false;
            mutationCalls += 1;
            if (mutation === "revision") {
              contextState.revision = "dd".repeat(32);
            } else {
              controller.cancel();
            }
          }
          return pre.issuedAt;
        },
        providerFactory: ({ incrementGet, incrementSign }) => new Proxy({
          async getPublicKey() {
            incrementGet();
            return pre.subject;
          },
          async signEvent() {
            incrementSign();
            return event;
          }
        }, {
          getOwnPropertyDescriptor(target, name) {
            if (name === method) armed = true;
            return Reflect.getOwnPropertyDescriptor(target, name);
          }
        })
      });
      controller = instance.controller;
      const label = `${method}/${mutation}`;
      await assertPublicDenial(() => approve(controller), label);
      assert.equal(mutationCalls, 1, label);
      assert.deepEqual(instance.counts(), {
        getPublicKeyCalls: method === "signEvent" ? 1 : 0,
        resolveCalls: 1,
        signEventCalls: 0
      }, label);
      assert.equal(boundary.state().persistCalls, 0, label);
      assert.equal(boundary.state().signedAttempt, undefined, label);
    }
  }
});

test("post-signer clock changes persist evidence once before public denial", async () => {
  for (const mutation of ["revision", "cancel"]) {
    const contextState = fullContextState();
    const race = clockAuthorityRace(mutation, contextState);
    const boundary = durableBoundary();
    const instance = setup({
      boundary,
      contextState,
      nowMs: race.nowMs,
      providerFactory: ({ incrementGet, incrementSign }) => ({
        async getPublicKey() { incrementGet(); return pre.subject; },
        async signEvent() {
          incrementSign();
          race.arm();
          return event;
        }
      })
    });
    race.attach(instance.controller);
    await assertPublicDenial(
      () => approve(instance.controller),
      `post-signer/pre-persistence/${mutation}`
    );
    assert.equal(race.calls(), 1, mutation);
    assert.equal(instance.counts().signEventCalls, 1, mutation);
    assert.equal(boundary.state().persistCalls, 1, mutation);
    assert.equal(typeof boundary.state().signedAttempt, "string", mutation);
  }
});

test("direct validation-now clock changes persist evidence once before denial", async () => {
  for (const mutation of ["revision", "cancel"]) {
    const contextState = fullContextState();
    const race = clockAuthorityRace(mutation, contextState);
    const inner = durableBoundary();
    const boundary = {
      ...inner,
      async persistSignedAttempt(claim, wire) {
        const result = await inner.persistSignedAttempt(claim, wire);
        race.arm();
        return result;
      }
    };
    const instance = setup({
      boundary,
      contextState,
      nowMs: race.nowMs
    });
    race.attach(instance.controller);
    await assertPublicDenial(
      () => approve(instance.controller),
      `direct-validation-now/${mutation}`
    );
    assert.equal(race.calls(), 1, mutation);
    assert.equal(instance.counts().signEventCalls, 1, mutation);
    assert.equal(inner.state().persistCalls, 1, mutation);
    assert.equal(typeof inner.state().signedAttempt, "string", mutation);
  }
});

test("captured Reflect.apply ignores descriptor-time global poisoning", async () => {
  for (const poisonAt of ["getPublicKey", "signEvent"]) {
    const originalDescriptor = Object.getOwnPropertyDescriptor(Reflect, "apply");
    let poisonArmed = false;
    let poisonInstalled = false;
    let wrapperCalls = 0;
    const boundary = durableBoundary();
    let counts;
    let persistCalls;
    let wire;
    try {
      const instance = setup({
        boundary,
        nowMs() {
          if (poisonArmed && !poisonInstalled) {
            poisonInstalled = true;
            Object.defineProperty(Reflect, "apply", {
              ...originalDescriptor,
              value(targetFunction, thisArgument, argumentsList) {
                wrapperCalls += 1;
                originalDescriptor.value(
                  targetFunction,
                  thisArgument,
                  argumentsList
                );
                return originalDescriptor.value(
                  targetFunction,
                  thisArgument,
                  argumentsList
                );
              }
            });
          }
          return pre.issuedAt;
        },
        providerFactory: ({ incrementGet, incrementSign }) => new Proxy({
          async getPublicKey() {
            incrementGet();
            return pre.subject;
          },
          async signEvent() {
            incrementSign();
            return event;
          }
        }, {
          getOwnPropertyDescriptor(target, name) {
            const descriptor = Reflect.getOwnPropertyDescriptor(target, name);
            if (name === poisonAt && !poisonInstalled) {
              poisonArmed = true;
            }
            return descriptor;
          }
        })
      });
      wire = await approve(instance.controller);
      counts = instance.counts();
      persistCalls = boundary.state().persistCalls;
    } finally {
      Object.defineProperty(Reflect, "apply", originalDescriptor);
    }
    assert.deepEqual(
      Object.getOwnPropertyDescriptor(Reflect, "apply"),
      originalDescriptor,
      poisonAt
    );
    assert.equal(typeof wire, "string", poisonAt);
    assert.equal(poisonInstalled, true, poisonAt);
    assert.equal(wrapperCalls, 0, poisonAt);
    assert.deepEqual(counts, {
      getPublicKeyCalls: 1,
      resolveCalls: 1,
      signEventCalls: 1
    }, poisonAt);
    assert.equal(persistCalls, 1, poisonAt);
  }
});

test("source exposes no publish/relay/dispatch operation and retains no provider field", async () => {
  const source = await readFile(new URL(
    "../web/mobile-device-authorization-seams-v2.mjs",
    import.meta.url
  ), "utf8");
  const executable = source.replace(/^\s*\/\/.*$/gm, "");
  assert.doesNotMatch(executable,
    /fetch\(|XMLHttpRequest|WebSocket|\.publish\s*\(|relay\s*\(|dispatch\s*\(/);
  assert.doesNotMatch(source, /this\.provider|provider\s*:/);
  assert.equal(source.match(/timeStillValid\(envelope\)/g)?.length, 1);
  assert.match(source, /const timeAndSyncCheck = \(includeCancellation = true\) => \{\s*timeStillValid\(envelope\);\s*syncCheck\(initial, includeCancellation\);\s*\};/);
  assert.match(source, /const reflectApply = Reflect\.apply;/);
  assert.doesNotMatch(source, /await Reflect\.apply\s*\(/);
  assert.equal(source.match(/await reflectApply\s*\(/g)?.length, 2);
  assert.match(source, /const validationNowMs = nowMs\(\);\s*syncCheck\(initial\);\s*await validateAuthorizationTimeV2\(\s*authorizationWire,\s*validationNowMs,/);
  assert.deepEqual(Object.keys(setup().controller).sort(), ["approve", "cancel"]);
});
