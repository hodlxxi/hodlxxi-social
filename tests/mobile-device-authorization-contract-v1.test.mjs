import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { canonicalMessagingDeviceJson as canonical } from "../web/messaging-device-authorization-v1.mjs";
import {
  METHODS, createMobileAuthorization, parseMobileAuthorization, mobileDigest,
  mobileUnsignedEvent, verifyMobileEvent, parseMobileEventRetry,
  createPairingQr, parsePairingQr, pairingSecretCommitment, phoneExchangeCommitment,
  pairingComparisonCode, pairingPossessionProof, verifyPairingScan, parseMobileJson,
  legacyChallengeSigningDigest, parseLegacyChallengeSubmission, parsePhoneSessionExchangeIdentity
} from "../web/mobile-device-authorization-contract-v1.mjs";
import { createDesktopPhoneApproval, preparePhoneMessagingDevice } from "../web/mobile-device-authorization-seams-v1.mjs";

const vectors = JSON.parse(await readFile(new URL("./fixtures/social_mobile_device_authorization_v1.json", import.meta.url), "utf8"));
const cryptoImpl = webcrypto;
const subject = vectors.subject;
const options = (entry, method) => ({ subject, now: entry.now, proposal: entry.proposal, expectedMethod: method, cryptoImpl });
const context = (method) => method === METHODS.nostr ? null : method === METHODS.legacy ? vectors.legacyContext : vectors.pairingContext;
const sourceFor = (entry, method) => createMobileAuthorization(
  method === METHODS.qr ? entry[method].content : entry.content, canonical(context(method)), method, options(entry, method)
);
const eventFor = async (entry, method) => {
  const source = await sourceFor(entry, method);
  const { unsignedEvent } = await mobileUnsignedEvent(source, options(entry, method));
  return { ...unsignedEvent, pubkey: subject, id: entry[method].eventId, sig: entry[method].signature };
};
const submissionFor = (entry) => canonical({ method: METHODS.legacy, ...vectors.legacyContext,
  authorizationDigest: entry[METHODS.legacy].digest, compressedPublicKey: vectors.compressedPublicKey,
  signature: entry[METHODS.legacy].signature });
const first = vectors.entries[0];
const qr = createPairingQr(vectors.pairingContext.pairingId, vectors.pairingSecret);

for (const entry of vectors.entries) for (const method of Object.values(METHODS)) {
  test(`${entry.operation}: independent ${method} canonical digest and cryptographic vector`, async () => {
    const source = await sourceFor(entry, method);
    const parsed = await parseMobileAuthorization(source, options(entry, method));
    assert.equal(parsed.digest, entry[method].digest);
    assert.equal(parsed.semantic.bindingId, entry.bindingId);
    assert.equal(parsed.semantic.action, entry.operation);
    assert.equal(await mobileDigest(entry.content, cryptoImpl), entry.semanticDigest);
    assert.equal(parsed.replayIds[0], "request:" + entry.proposal.requestId);
    if (method === METHODS.legacy) {
      assert.equal(await legacyChallengeSigningDigest(vectors.legacyContext.challenge, cryptoImpl), entry[method].signingDigest);
      assert.equal((await parseLegacyChallengeSubmission(source, submissionFor(entry), options(entry, method))).signingDigest,
        entry[method].signingDigest);
    } else {
      const event = await eventFor(entry, method);
      assert.equal((await verifyMobileEvent(source, event, options(entry, method))).id, entry[method].eventId);
      const retry = canonical({ authorization: source, signedEvent: event, signatureFormat: "nostr_event_id_bip340_v1" });
      assert.deepEqual(await parseMobileEventRetry(source, retry, options(entry, method)), event);
      if (method === METHODS.qr) {
        assert.equal(pairingComparisonCode(parsed.digest), entry[method].comparisonCode);
        assert.equal(await pairingPossessionProof(vectors.pairingSecret, parsed.digest, cryptoImpl), entry[method].possessionProof);
        if (entry.operation !== "revoke") {
          assert.equal(await mobileDigest(entry[method].exchangeIdentity, cryptoImpl), entry[method].exchangeIdentityDigest);
          const exchange = await parsePhoneSessionExchangeIdentity(entry[method].exchangeIdentity,
            { authorization: source, verifier: vectors.exchangeVerifier, ...options(entry, method) });
          assert.equal(exchange.bindingId, entry.bindingId);
        } else {
          await assert.rejects(parsePhoneSessionExchangeIdentity("{}",
            { authorization: source, verifier: vectors.exchangeVerifier, ...options(entry, method) }));
        }
        await assert.rejects(parsePhoneSessionExchangeIdentity(entry[method].exchangeIdentity,
          { authorization: source, verifier: vectors.pairingSecret, ...options(entry, method) }));
      }
    }
  });
}

test("all cross-method and cross-operation substitutions fail", async () => {
  for (const entry of vectors.entries) for (const method of Object.values(METHODS)) {
    const source = await sourceFor(entry, method);
    for (const otherMethod of Object.values(METHODS).filter((m) => m !== method)) {
      await assert.rejects(parseMobileAuthorization(source, options(entry, otherMethod)));
      if (method !== METHODS.legacy && otherMethod !== METHODS.legacy) {
        await assert.rejects(verifyMobileEvent(await sourceFor(entry, otherMethod), await eventFor(entry, method), options(entry, otherMethod)));
      }
    }
    for (const other of vectors.entries.filter((e) => e !== entry)) {
      await assert.rejects(parseMobileAuthorization(source, { ...options(entry, method), proposal: other.proposal }));
    }
  }
});

for (const [field, replacement] of Object.entries({
  subject: "ab".repeat(32), deviceId: "ab".repeat(32), publicKey: "0b" + "00".repeat(31),
  requestId: "ab".repeat(32), operation: "rotate", version: 2, bindingVersion: 2,
  priorBindingId: "ab".repeat(32), expiresAt: "2026-09-08T22:34:58Z"
})) test(`LEGACY original record rejects proposal substitution: ${field}`, async () => {
  const source = await sourceFor(first, METHODS.legacy);
  const changed = JSON.parse(source);
  const content = JSON.parse(changed.content);
  content.authorization[field] = replacement;
  changed.content = canonical(content);
  // Recompute every caller-controlled field; the original challenge record's
  // digest in the signed-login submission must still match byte-for-byte.
  await assert.rejects(parseLegacyChallengeSubmission(canonical(changed), submissionFor(first), options(first, METHODS.legacy)));
});

test("LEGACY wrong challenge, context, digest, expiry and caller signature shape fail", async () => {
  const source = await sourceFor(first, METHODS.legacy);
  for (const [field, value] of Object.entries({ challenge: "12345678-1234-4234-8234-123456789abd",
    loginContext: "ff".repeat(32), authorizationDigest: "ff".repeat(32), method: METHODS.qr,
    compressedPublicKey: "02" + "ab".repeat(32), signature: "invalid" })) {
    await assert.rejects(parseLegacyChallengeSubmission(source, canonical({ ...JSON.parse(submissionFor(first)), [field]: value }), options(first, METHODS.legacy)));
  }
  for (const now of [first.now - 1, first.now + 300]) {
    await assert.rejects(parseLegacyChallengeSubmission(source, submissionFor(first), { ...options(first, METHODS.legacy), now }));
  }
});

test("QR locator contains only one-shot locator/secret; scan grants no access", async () => {
  assert.deepEqual(Object.keys(parsePairingQr(qr)).sort(), ["pairingId", "secret"]);
  assert.ok(!qr.includes(subject));
  assert.equal(await pairingSecretCommitment(vectors.pairingSecret, cryptoImpl), vectors.pairingContext.secretCommitment);
  assert.equal(await phoneExchangeCommitment(vectors.exchangeVerifier, cryptoImpl), vectors.pairingContext.exchangeCommitment);
  const source = await sourceFor(first, METHODS.qr);
  const scanned = await verifyPairingScan(source, { qr, possessionProof: first[METHODS.qr].possessionProof, ...options(first, METHODS.qr) });
  assert.deepEqual(scanned, { state: "awaiting-approval", transcriptDigest: first[METHODS.qr].digest,
    comparisonCode: first[METHODS.qr].comparisonCode });
  for (const invalid of [qr + ":extra", qr + "?subject=" + subject, "https://example.test/" + qr, qr.toUpperCase()]) {
    assert.throws(() => parsePairingQr(invalid));
  }
  await assert.rejects(verifyPairingScan(source, { qr: createPairingQr(vectors.pairingContext.pairingId, "ff".repeat(32)),
    possessionProof: first[METHODS.qr].possessionProof, ...options(first, METHODS.qr) }));
  await assert.rejects(verifyPairingScan(source, { qr, possessionProof: "ff".repeat(32), ...options(first, METHODS.qr) }));
  await assert.rejects(verifyPairingScan(source, { qr, possessionProof: first[METHODS.qr].possessionProof,
    ...options(first, METHODS.qr), now: first.now + 300 }));
});

test("unknown/private fields, duplicate JSON and invalid X25519 encodings fail", async () => {
  const source = await sourceFor(first, METHODS.qr);
  for (const field of ["privateKey", "participantPrivateKey", "K_message", "access_token", "password", "seed"]) {
    const root = JSON.parse(source);
    root.context[field] = "prohibited";
    await assert.rejects(parseMobileAuthorization(canonical(root), options(first, METHODS.qr)));
  }
  for (const invalid of [" " + source, source.replace('"version":1', '"version":1,"version":1'), source + "\n"]) {
    assert.throws(() => parseMobileJson(invalid));
  }
  for (const key of ["00".repeat(32), "01" + "00".repeat(31), "ff".repeat(32),
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900"]) {
    const root = JSON.parse(source), semantic = JSON.parse(root.content);
    semantic.authorization.publicKey = key; root.content = canonical(semantic);
    await assert.rejects(parseMobileAuthorization(canonical(root), { ...options(first, METHODS.qr), proposal: undefined }));
  }
});

// Paired fixture coverage is checked against UBID's canonical validator and
// constants there; neither repository needs the other's source at test time.
for (const method of Object.values(METHODS)) {
  test(`shared complete X25519 prohibited set rejects ${method}`, async () => {
    const source = await sourceFor(first, method);
    for (const key of new Set(Object.values(vectors.x25519NegativeVectors).flat())) {
      const root = JSON.parse(source), semantic = JSON.parse(root.content);
      semantic.authorization.publicKey = key;
      root.content = canonical(semantic);
      await assert.rejects(parseMobileAuthorization(canonical(root),
        { ...options(first, method), proposal: undefined }), `accepted prohibited X25519 encoding: ${key}`);
    }
    // The unchanged positive carrier still passes the same consumer boundary.
    await parseMobileAuthorization(source, options(first, method));
  });
}

const approvalHarness = async (overrides = {}) => {
  const authorization = await sourceFor(first, METHODS.qr);
  const event = await eventFor(first, METHODS.qr);
  let state = { subject, revision: "cc".repeat(32), pairingId: vectors.pairingContext.pairingId,
    transcriptDigest: first[METHODS.qr].digest };
  let claimed = false;
  const calls = [], retries = [];
  const config = { enabled: true, cryptoImpl, now: () => first.now, getContext: () => state,
    claimApproval: async () => { calls.push("claim"); if (claimed) return false; claimed = true; return true; },
    persistRetry: async (retry) => { calls.push("persist"); retries.push(retry); },
    resolveProvider: () => { calls.push("resolve"); return {
      getPublicKey: async () => { calls.push("key"); return subject; },
      signEvent: async (unsigned) => { calls.push("sign"); assert.equal(unsigned.content, authorization); return event; }
    }; }, ...overrides };
  return { config, calls, retries, controller: createDesktopPhoneApproval(config), replace: (v) => { state = { ...state, ...v }; },
    action: { authorization, comparisonCode: first[METHODS.qr].comparisonCode, proposal: first.proposal } };
};

test("only explicit desktop approval acquires NIP-07 and calls signEvent exactly once", async () => {
  const h = await approvalHarness();
  assert.deepEqual(h.calls, []);
  const retry = await h.controller.approve(h.action);
  assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist"]);
  assert.equal(h.retries[0], retry);
  assert.ok(!/privateKey|K_message|access_token/.test(retry));
  assert.ok(!retry.includes(vectors.pairingSecret));
  assert.ok(!retry.includes(vectors.exchangeVerifier));
  await parseMobileEventRetry(h.action.authorization, retry, options(first, METHODS.qr));
  await assert.rejects(h.controller.approve(h.action));
  await assert.rejects(createDesktopPhoneApproval(h.config).approve(h.action));
  assert.equal(h.calls.filter((v) => v === "sign").length, 1);
});

const signerUnavailable = { name: "TypeError", message: "messaging device authorization unavailable" };

test("desktop approval awaits claim before class prototype methods, with one call each and the provider as this", async () => {
  const h = await approvalHarness();
  const event = await eventFor(first, METHODS.qr);
  class BaseProvider {
    async getPublicKey() {
      assert.equal(this, provider);
      h.calls.push("key");
      return subject;
    }
  }
  class Provider extends BaseProvider {
    async signEvent(unsigned) {
      assert.equal(this, provider);
      h.calls.push("sign");
      assert.deepEqual(unsigned, (await mobileUnsignedEvent(h.action.authorization, options(first, METHODS.qr))).unsignedEvent);
      return event;
    }
  }
  const provider = new Provider();
  assert.notEqual(Object.getPrototypeOf(provider), Object.prototype);
  assert.equal(Object.hasOwn(provider, "getPublicKey"), false);
  assert.equal(Object.hasOwn(provider, "signEvent"), false);
  let releaseClaim, signalClaim;
  const claimPending = new Promise((resolve) => { releaseClaim = resolve; });
  const claimStarted = new Promise((resolve) => { signalClaim = resolve; });
  const controller = createDesktopPhoneApproval({ ...h.config,
    claimApproval: async (claim) => {
      assert.deepEqual(claim, { revision: "cc".repeat(32), pairingId: vectors.pairingContext.pairingId,
        transcriptDigest: first[METHODS.qr].digest });
      const claimed = await h.config.claimApproval(claim);
      signalClaim();
      await claimPending;
      return claimed;
    },
    resolveProvider: () => { h.calls.push("resolve"); return provider; }
  });
  assert.deepEqual(h.calls, []);
  const approval = controller.approve(h.action);
  await claimStarted;
  assert.deepEqual(h.calls, ["claim"]);
  releaseClaim();
  const retry = await approval;
  assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist"]);
  assert.deepEqual(h.retries, [retry]);
  assert.deepEqual(await parseMobileEventRetry(h.action.authorization, retry, options(first, METHODS.qr)), event);
  await assert.rejects(controller.approve(h.action));
  assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist"]);
});

test("desktop approval rejects prototype subject mismatch before signEvent inspection", async () => {
  for (const returnedKey of ["ff".repeat(32), subject.toUpperCase()]) {
    const h = await approvalHarness();
    let signInspections = 0;
    class Provider {
      async getPublicKey() { h.calls.push("key"); return returnedKey; }
      async signEvent() { h.calls.push("sign"); }
    }
    const provider = new Proxy(new Provider(), {
      getOwnPropertyDescriptor(target, name) {
        if (name === "signEvent") signInspections += 1;
        return Object.getOwnPropertyDescriptor(target, name);
      }
    });
    const controller = createDesktopPhoneApproval({ ...h.config,
      resolveProvider: () => { h.calls.push("resolve"); return provider; }
    });
    await assert.rejects(controller.approve(h.action), signerUnavailable);
    assert.deepEqual(h.calls, ["claim", "resolve", "key"]);
    assert.equal(signInspections, 0);
    assert.deepEqual(h.retries, []);
  }
});

test("desktop approval rejects own and inherited accessors and non-function shadows without invoking them", async () => {
  for (const name of ["getPublicKey", "signEvent"]) {
    for (const location of ["own", "prototype"]) {
      for (const descriptorType of ["getter", "setter", "non-function"]) {
        const h = await approvalHarness();
        let accessorCalls = 0;
        const methods = {
          async getPublicKey() { h.calls.push("key"); return subject; },
          async signEvent() { h.calls.push("sign"); }
        };
        const prototype = Object.create(methods);
        const provider = Object.create(prototype);
        const descriptor = descriptorType === "getter" ? {
          get() { accessorCalls += 1; return Object.getOwnPropertyDescriptor(methods, name).value; }
        } : descriptorType === "setter" ? {
          set(value) { accessorCalls += 1; }
        } : { value: undefined };
        Object.defineProperty(location === "own" ? provider : prototype, name, descriptor);
        const controller = createDesktopPhoneApproval({ ...h.config,
          resolveProvider: () => { h.calls.push("resolve"); return provider; }
        });
        await assert.rejects(controller.approve(h.action), signerUnavailable, `${name} ${location} ${descriptorType}`);
        assert.equal(accessorCalls, 0);
        assert.deepEqual(h.calls, ["claim", "resolve", ...(name === "signEvent" ? ["key"] : [])]);
        assert.deepEqual(h.retries, []);
      }
    }
  }
});

test("desktop approval keeps provider and prototype inspection failures generic", async () => {
  for (const name of ["getPublicKey", "signEvent"]) {
    for (const trap of ["getOwnPropertyDescriptor", "getPrototypeOf"]) {
      for (const location of ["own", "prototype"]) {
        const h = await approvalHarness();
        let inspections = 0;
        const target = name === "signEvent" ? {
          async getPublicKey() { h.calls.push("key"); return subject; }
        } : {};
        const inspected = new Proxy(target, {
          [trap](object, key) {
            if (trap === "getOwnPropertyDescriptor" && key !== name) return Object.getOwnPropertyDescriptor(object, key);
            inspections += 1;
            throw new Error("private extension inspection detail");
          }
        });
        const provider = location === "own" ? inspected : Object.create(inspected);
        const controller = createDesktopPhoneApproval({ ...h.config,
          resolveProvider: () => { h.calls.push("resolve"); return provider; }
        });
        await assert.rejects(controller.approve(h.action), signerUnavailable, `${name} ${trap} ${location}`);
        assert.equal(inspections, 1);
        assert.deepEqual(h.calls, ["claim", "resolve", ...(name === "signEvent" ? ["key"] : [])]);
        assert.deepEqual(h.retries, []);
      }
    }
  }
});

test("desktop approval accepts methods at the eighth level and rejects methods beyond the bound", async () => {
  for (const name of ["getPublicKey", "signEvent"]) for (const depth of [7, 8]) {
    const h = await approvalHarness();
    const event = await eventFor(first, METHODS.qr);
    const methods = {
      async getPublicKey() { assert.equal(this, provider); h.calls.push("key"); return subject; },
      async signEvent() { assert.equal(this, provider); h.calls.push("sign"); return event; }
    };
    let provider = Object.create(null, { [name]: Object.getOwnPropertyDescriptor(methods, name) });
    for (let level = 0; level < depth; level += 1) provider = Object.create(provider);
    const other = name === "getPublicKey" ? "signEvent" : "getPublicKey";
    Object.defineProperty(provider, other, Object.getOwnPropertyDescriptor(methods, other));
    const controller = createDesktopPhoneApproval({ ...h.config,
      resolveProvider: () => { h.calls.push("resolve"); return provider; }
    });
    if (depth === 7) {
      const retry = await controller.approve(h.action);
      assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist"]);
      assert.deepEqual(h.retries, [retry]);
    } else {
      await assert.rejects(controller.approve(h.action), signerUnavailable);
      assert.deepEqual(h.calls, ["claim", "resolve", ...(name === "signEvent" ? ["key"] : [])]);
      assert.deepEqual(h.retries, []);
    }
  }
});

test("desktop approval bounds cyclic prototype inspection and never reads provider properties", async () => {
  for (const name of ["getPublicKey", "signEvent"]) {
    const h = await approvalHarness();
    let inspections = 0, propertyReads = 0;
    const provider = new Proxy({}, {
      get() { propertyReads += 1; throw new Error("unexpected property access"); },
      getOwnPropertyDescriptor(target, key) {
        if (key !== name) return { configurable: true, value: async () => { h.calls.push("key"); return subject; } };
        inspections += 1;
        if (inspections > 8) throw new Error("prototype traversal exceeded its bound");
        return undefined;
      },
      getPrototypeOf() { return provider; }
    });
    const controller = createDesktopPhoneApproval({ ...h.config,
      resolveProvider: () => { h.calls.push("resolve"); return provider; }
    });
    await assert.rejects(controller.approve(h.action), signerUnavailable);
    assert.equal(inspections, 8);
    assert.equal(propertyReads, 0);
    assert.deepEqual(h.calls, ["claim", "resolve", ...(name === "signEvent" ? ["key"] : [])]);
    assert.deepEqual(h.retries, []);
  }
});

test("desktop approval rejects null and non-object providers", async () => {
  const callableProvider = Object.assign(() => {}, {
    getPublicKey() { assert.fail("function provider must not be called"); },
    signEvent() { assert.fail("function provider must not sign"); }
  });
  for (const provider of [null, undefined, false, 42, subject, callableProvider]) {
    const h = await approvalHarness({ resolveProvider: () => provider });
    await assert.rejects(h.controller.approve(h.action), signerUnavailable);
    assert.deepEqual(h.calls, ["claim"]);
    assert.deepEqual(h.retries, []);
  }
});

test("desktop approval rechecks context and expiry after prototype getPublicKey before resolving signEvent", async () => {
  for (const mutation of ["subject", "revision", "pairingId", "transcriptDigest", "cancel", "expiry"]) {
    const h = await approvalHarness();
    const parsed = await parseMobileAuthorization(h.action.authorization, options(first, METHODS.qr));
    let currentTime = first.now, signInspections = 0;
    class Provider {
      async getPublicKey() {
        h.calls.push("key");
        await Promise.resolve();
        if (mutation === "cancel") controller.cancel();
        else if (mutation === "expiry") currentTime = parsed.semantic.expiresAt;
        else h.replace({ [mutation]: "ff".repeat(32) });
        return subject;
      }
      async signEvent() { h.calls.push("sign"); }
    }
    const provider = new Proxy(new Provider(), {
      getOwnPropertyDescriptor(target, name) {
        if (name === "signEvent") signInspections += 1;
        return Object.getOwnPropertyDescriptor(target, name);
      }
    });
    const controller = createDesktopPhoneApproval({ ...h.config, now: () => currentTime,
      resolveProvider: () => { h.calls.push("resolve"); return provider; }
    });
    await assert.rejects(controller.approve(h.action), signerUnavailable, mutation);
    assert.deepEqual(h.calls, ["claim", "resolve", "key"]);
    assert.equal(signInspections, 0);
    assert.deepEqual(h.retries, []);
  }
});

test("mismatched human transcript and disabled mode never acquire signer", async () => {
  for (const changes of [{ comparisonCode: "0000-0000-0000" }, { proposal: vectors.entries[1].proposal }]) {
    const h = await approvalHarness();
    await assert.rejects(h.controller.approve({ ...h.action, ...changes }));
    assert.deepEqual(h.calls, []);
  }
  const h = await approvalHarness({ enabled: false });
  await assert.rejects(h.controller.approve(h.action));
  assert.deepEqual(h.calls, []);
});

test("subject change, cross-tab replacement, cancellation and wrong extension key prevent signing", async () => {
  for (const mutation of ["subject", "revision", "pairingId", "cancel", "wrong-key"]) {
    const h = await approvalHarness();
    let signs = 0;
    const controller = createDesktopPhoneApproval({ ...h.config, resolveProvider: () => ({
      async getPublicKey() {
        if (mutation === "cancel") controller.cancel();
        else if (mutation !== "wrong-key") h.replace({ [mutation]: "ff".repeat(32) });
        return mutation === "wrong-key" ? "ff".repeat(32) : subject;
      },
      async signEvent() { signs += 1; throw new Error("must not sign"); }
    }) });
    await assert.rejects(controller.approve(h.action));
    assert.equal(signs, 0);
    assert.equal(h.retries.length, 0);
  }
});

for (const interruptedAt of ["resolve", "key", "sign"]) {
  test(`interruption after approval claim at ${interruptedAt} never retries approval or signing`, async () => {
    const h = await approvalHarness();
    const interrupted = new Error("synthetic user abort");
    const config = { ...h.config, resolveProvider: () => {
      h.calls.push("resolve");
      if (interruptedAt === "resolve") throw interrupted;
      return {
        async getPublicKey() {
          h.calls.push("key");
          if (interruptedAt === "key") throw interrupted;
          return subject;
        },
        async signEvent() { h.calls.push("sign"); throw interrupted; }
      };
    } };
    const controller = createDesktopPhoneApproval(config);
    let returned;
    await assert.rejects(async () => { returned = await controller.approve(h.action); });
    assert.equal(returned, undefined);
    assert.deepEqual(h.retries, []);
    const expected = ["claim", "resolve", ...(interruptedAt === "resolve" ? [] : ["key"]),
      ...(interruptedAt === "sign" ? ["sign"] : [])];
    assert.deepEqual(h.calls, expected);
    await assert.rejects(controller.approve(h.action));
    await assert.rejects(createDesktopPhoneApproval(config).approve(h.action));
    assert.deepEqual(h.calls, [...expected, "claim"]);
    // The abandoned claim stays consumed. Durable cancellation/expiry and a
    // fresh pairing are Phase 2 work; no authorization result exists here.
  });
}

for (const outcome of ["before-write", "partial-write", "after-write"]) {
  test(`ambiguous post-signature persistence ${outcome} never returns authorization or resigns`, async () => {
    const h = await approvalHarness();
    let stored, attempted, returned;
    const config = { ...h.config, persistRetry: async (retry) => {
      h.calls.push("persist");
      attempted = retry;
      if (outcome === "partial-write") stored = retry.slice(0, -1);
      if (outcome === "after-write") stored = retry;
      throw new Error("synthetic persistence acknowledgement lost");
    } };
    const controller = createDesktopPhoneApproval(config);
    await assert.rejects(async () => { returned = await controller.approve(h.action); });
    assert.equal(returned, undefined);
    assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist"]);
    await assert.rejects(controller.approve(h.action));
    await assert.rejects(createDesktopPhoneApproval(config).approve(h.action));
    assert.deepEqual(h.calls, ["claim", "resolve", "key", "sign", "persist", "claim"]);
    if (outcome === "after-write") {
      assert.equal(stored, attempted);
      assert.deepEqual(await parseMobileEventRetry(h.action.authorization, stored, options(first, METHODS.qr)),
        await eventFor(first, METHODS.qr));
      await assert.rejects(parseMobileEventRetry(await sourceFor(vectors.entries[1], METHODS.qr), stored,
        options(vectors.entries[1], METHODS.qr)));
    } else {
      await assert.rejects(parseMobileEventRetry(h.action.authorization, stored, options(first, METHODS.qr)));
    }
    // An exact persisted public retry is only verified evidence. Reconciliation,
    // terminal cancellation/expiry and session issuance remain Phase 2 work.
    assert.deepEqual(h.retries, []);
  });
}

test("phone pre-login preparation persists a non-extractable X25519 key and never touches a signer", async () => {
  let record, commits = 0;
  const store = {
    read: async () => record && structuredClone(record),
    create: async (next) => { assert.equal(record, undefined); record = structuredClone(next); commits += 1; }
  };
  const original = Object.getOwnPropertyDescriptor(globalThis, "nostr");
  Object.defineProperty(globalThis, "nostr", { configurable: true, get() { assert.fail("phone acquired NIP-07"); } });
  try {
    const proposal = await preparePhoneMessagingDevice({ enabled: true, subject, store, cryptoImpl,
      CryptoKeyImpl: webcrypto.CryptoKey });
    assert.equal(commits, 1);
    assert.equal(record.privateKey.extractable, false);
    await assert.rejects(cryptoImpl.subtle.exportKey("pkcs8", record.privateKey));
    const content = JSON.parse(first.content);
    Object.assign(content.authorization, { deviceId: proposal.deviceId, publicKey: proposal.publicKey, requestId: proposal.requestId });
    const bound = await createMobileAuthorization(canonical(content), canonical(vectors.legacyContext), METHODS.legacy,
      { subject, proposal, now: first.now, cryptoImpl });
    assert.ok(!/privateKey|K_message|access_token/.test(bound));
    assert.equal((await parseMobileAuthorization(bound, { subject, proposal, now: first.now, expectedMethod: METHODS.legacy, cryptoImpl })).semantic.binding.publicKey, proposal.publicKey);
    await assert.rejects(preparePhoneMessagingDevice({ enabled: true, subject, store, cryptoImpl, CryptoKeyImpl: webcrypto.CryptoKey }));
  } finally {
    if (original) Object.defineProperty(globalThis, "nostr", original); else delete globalThis.nostr;
  }
});

test("phone disabled, storage failure or changed context cannot release a proposal", async () => {
  await assert.rejects(preparePhoneMessagingDevice({ subject, store: { read() { assert.fail("disabled storage access"); } } }));
  let calls = 0;
  await assert.rejects(preparePhoneMessagingDevice({ enabled: true, subject, store: { read: async () => undefined },
    cryptoImpl, CryptoKeyImpl: webcrypto.CryptoKey, contextStillCurrent: () => ++calls < 2 }));
  await assert.rejects(preparePhoneMessagingDevice({ enabled: true, subject,
    store: { read: async () => undefined, create: async () => { throw new Error("commit failed"); } },
    cryptoImpl, CryptoKeyImpl: webcrypto.CryptoKey }));
});

for (const interruptedAt of ["committed-write", "readback"]) {
  test(`phone key stored but context fails at ${interruptedAt}: no proposal or implicit replacement`, async () => {
    let record, current = true, creates = 0, generates = 0, returned;
    const exports = [];
    const store = {
      async read() {
        if (record && interruptedAt === "readback") current = false;
        return record && structuredClone(record);
      },
      async create(next) {
        assert.equal(record, undefined);
        record = structuredClone(next);
        creates += 1;
        if (interruptedAt === "committed-write") current = false;
      }
    };
    const observedCrypto = {
      getRandomValues: (value) => cryptoImpl.getRandomValues(value),
      subtle: {
        generateKey: (...args) => { generates += 1; return cryptoImpl.subtle.generateKey(...args); },
        exportKey: (format, key) => {
          exports.push([format, key.type]);
          assert.equal(key.type, "public");
          return cryptoImpl.subtle.exportKey(format, key);
        }
      }
    };
    const config = { enabled: true, subject, store, cryptoImpl: observedCrypto,
      CryptoKeyImpl: webcrypto.CryptoKey, contextStillCurrent: () => current };
    await assert.rejects(async () => { returned = await preparePhoneMessagingDevice(config); });
    assert.equal(returned, undefined);
    assert.equal(record.state, "pending-register");
    assert.equal(record.acceptedBinding, null);
    assert.equal(record.authorization, null);
    assert.equal(record.pendingAuthorization, null);
    assert.equal(record.privateKey.extractable, false);
    await assert.rejects(cryptoImpl.subtle.exportKey("pkcs8", record.privateKey));
    const original = record;
    current = true;
    await assert.rejects(preparePhoneMessagingDevice(config));
    assert.equal(record, original);
    assert.equal(creates, 1);
    assert.equal(generates, 1);
    assert.deepEqual(exports, [["raw", "public"]]);
    // Orphan/pending-key recovery or cleanup is deferred to Phase 2. The
    // occupied slot cannot silently register again, reuse or replace its key.
  });
}
