import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import {
  authorizeMessagingDeviceBinding,
  canonicalMessagingDeviceJson,
  canonicalMessagingDeviceAuthorizationProposal,
  composeMessagingDeviceAuthorizationPayload,
  createNip07MessagingDeviceSigner,
  parseMessagingDeviceAuthorizationIntent,
  parseMessagingDeviceAuthorizationRetry,
  signMessagingDeviceAuthorizationIntent
} from "../web/messaging-device-authorization-v1.mjs";
import {
  createNip46MessagingDeviceSigner
} from "../web/nip46-messaging-device-signer-v1.mjs";

const subject = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const deviceId = "22".repeat(32);
const requestId = "33".repeat(32);
const publicKey = "09" + "00".repeat(31);
const digest = "70aa19a24077c3365a836f0476660f0132ab7959615d2c8c67ba75afd9071d9c";
const eventId = "4fb89f90de1379e47893ad335c4839805be4265767d1972b7281aea2ef2e0ad0";
const signature =
  "6fb5dcbb6791eaf44bb2fa9282a1db21c702e88db58ab388d974baae4b082ff69" +
  "cfbfe4eb62fe36a8040fb9de010a1e6a9a2b6232332fac21d2d7a2a7e689570";
const content =
  '{"authorization":{"algorithm":"x25519-v1","bindingExpiresAt":"2026-10-08T22:29:59Z",' +
  '"bindingRecordSchema":"hodlxxi.social_messaging_device_binding_record.v1",' +
  '"bindingRecordVersion":1,"bindingValidFrom":"2026-09-08T22:29:59Z",' +
  '"bindingVersion":1,"deviceId":"' + deviceId + '","expiresAt":"2026-09-08T22:34:59Z",' +
  '"issuedAt":"2026-09-08T22:29:59Z","operation":"register","priorBindingId":null,' +
  '"publicKey":"' + publicKey + '","requestId":"' + requestId + '",' +
  '"schema":"hodlxxi.social_messaging_device_binding_authorization.v1","subject":"' + subject + '",' +
  '"version":1},"domain":"HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"}';
const claim = JSON.parse(content).authorization;
const tags = [
  ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
  ["semantic-digest", digest],
  ["request-id", requestId],
  ["action", "register"]
];
const unsignedEvent = { content, created_at: 1788906599, kind: 27236, tags };
const signedEvent = { ...unsignedEvent, id: eventId, pubkey: subject, sig: signature };
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const makeIntentToken = (changes = {}) => [
  b64({ alg: "RS256", kid: "service-key", typ: "hodlxxi-device-binding-intent+jwt" }),
  b64({
    iss: "https://identity.example", sub: subject, iat: 1788906599, exp: 1788906899,
    jti: requestId,
    aud: "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1",
    tokenUse: "device_binding_authorization_intent",
    purpose: "social_messaging_device_binding_authorization_intent_v1",
    claimType: "lifecycle", action: "register", digest, eventId,
    signatureFormat: "nostr_event_id_bip340_v1",
    ...changes
  }),
  "signature"
].join(".");
const intentToken = makeIntentToken();
const vectorNow = () => 1_788_906_599_000;
const vectorCrypto = { cryptoImpl: webcrypto, now: vectorNow };
const intent = () => ({
  schema: "hodlxxi.social_messaging_device_binding_authorization_intent.v1",
  version: 1,
  claimType: "lifecycle",
  claim: structuredClone(claim),
  digest,
  signatureFormat: "nostr_event_id_bip340_v1",
  expectedPubkey: subject,
  unsignedEvent: structuredClone(unsignedEvent),
  intentToken
});
const response = (value) => ({
  status: 200,
  headers: { get: () => "application/json" },
  text: async () => canonicalMessagingDeviceJson(value)
});
const registerAuthorizationResult = () => ({
  action: "register", active: true,
  authorizationExpiresAt: "2026-10-08T22:29:59Z",
  authorizationProofId: "hodlxxi-binding-authorization-v1-sha256:" + digest,
  authorizationValidFrom: "2026-09-08T22:29:59Z",
  bindingId: "6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d",
  bindingOperation: "register", bindingVersion: 1, deviceId,
  expiresAt: "2026-10-08T22:29:59Z", requestId,
  schema: "hodlxxi.social_messaging_device_binding_authorization_result.v1",
  validFrom: "2026-09-08T22:29:59Z", version: 1
});
const fixedIntent = ({ claimType, action, requestId: fixedRequestId, digest: fixedDigest,
  eventId: fixedEventId, envelope }) => {
  const fixedContent = canonicalMessagingDeviceJson(envelope);
  const fixedToken = [
    b64({ alg: "RS256", kid: "service-key", typ: "hodlxxi-device-binding-intent+jwt" }),
    b64({
      iss: "https://identity.example", sub: subject, iat: 1788906600, exp: 1788906900,
      jti: fixedRequestId,
      aud: "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1",
      tokenUse: "device_binding_authorization_intent",
      purpose: "social_messaging_device_binding_authorization_intent_v1",
      claimType, action, digest: fixedDigest, eventId: fixedEventId,
      signatureFormat: "nostr_event_id_bip340_v1"
    }),
    "signature"
  ].join(".");
  return {
    claim: claimType === "lifecycle" ? envelope.authorization : envelope.adoption,
    claimType,
    digest: fixedDigest,
    expectedPubkey: subject,
    intentToken: fixedToken,
    schema: "hodlxxi.social_messaging_device_binding_authorization_intent.v1",
    signatureFormat: "nostr_event_id_bip340_v1",
    unsignedEvent: {
      content: fixedContent,
      created_at: 1788906600,
      kind: 27236,
      tags: [
        ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
        ["semantic-digest", fixedDigest],
        ["request-id", fixedRequestId],
        ["action", action]
      ]
    },
    version: 1
  };
};

test("authoritative UBID register vector validates and NIP-07 signs exactly once", async () => {
  const parsed = await parseMessagingDeviceAuthorizationIntent(intent(), { subject, ...vectorCrypto });
  assert.equal(parsed.eventId, eventId);
  const calls = [];
  const signer = createNip07MessagingDeviceSigner({
    resolveProvider: () => ({
      async getPublicKey() { calls.push("getPublicKey"); return subject; },
      async signEvent(value) { calls.push(["signEvent", structuredClone(value)]); return signedEvent; }
    }),
    setTimer: () => 1,
    clearTimer() {}
  });
  const result = await signMessagingDeviceAuthorizationIntent(
    { subject, intent: intent() }, { signer, ...vectorCrypto }
  );
  assert.equal(result.signedEvent.id, eventId);
  assert.deepEqual(calls, ["getPublicKey", ["signEvent", unsignedEvent]]);
});

test("authoritative UBID rotate revoke and adoption carrier vectors verify byte-for-byte", async () => {
  const bindingId = "6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d";
  const rotateBindingId = "cc4efc97cef56180a86b1d9235b754fa717b45d4b9593ebdb04be4226c357b10";
  const baseLifecycle = {
    algorithm: "x25519-v1",
    bindingExpiresAt: "2026-10-08T22:29:59Z",
    bindingRecordSchema: "hodlxxi.social_messaging_device_binding_record.v1",
    bindingRecordVersion: 1,
    bindingValidFrom: "2026-09-08T22:30:00Z",
    deviceId,
    expiresAt: "2026-09-08T22:35:00Z",
    issuedAt: "2026-09-08T22:30:00Z",
    schema: "hodlxxi.social_messaging_device_binding_authorization.v1",
    subject,
    version: 1
  };
  const vectors = [
    {
      claimType: "lifecycle", action: "rotate", requestId: "44".repeat(32),
      digest: "16c47dd55844cf3086124b87249ec395b7d42759215f14ccfa99259fa51dd80c",
      eventId: "a429b02a9223fcb463d64da2483fc8ec644d2002889cdc9fa29ba1ec72732f28",
      signature: "c919383d95f589fe9661636b0365f4a0231654a929728d14b085a0f7f130efdb" +
        "64fe2f1975eb2f5ee67ccd80e01f8e7f17402fbb55e47f1de3e85921e9a67d93",
      envelope: { authorization: { ...baseLifecycle, bindingVersion: 2, operation: "rotate",
        priorBindingId: bindingId, publicKey: "0a" + "00".repeat(31), requestId: "44".repeat(32) },
        domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1" }
    },
    {
      claimType: "lifecycle", action: "revoke", requestId: "55".repeat(32),
      digest: "a7db4b3f77f902abfffe99ea33739b2c65f7a1ce2f0f313065e9f7bbdcdba8bb",
      eventId: "1da8e3972f9d82a15103a86de94ff06321e110065716baf5d3129a435063b2f6",
      signature: "d20c569136c2e96bd941ae5ca324afc5db716c736c9013b2ca43aab3391758da" +
        "eb6500f4e446fee52d7c7c2d2d79e37453684a9994d390afe75dbd148a7f295d",
      envelope: { authorization: { ...baseLifecycle, bindingVersion: 3, operation: "revoke",
        priorBindingId: rotateBindingId, publicKey: "0a" + "00".repeat(31), requestId: "55".repeat(32) },
        domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1" }
    }
  ];
  const bindingRecord = {
    algorithm: "x25519-v1", bindingVersion: 1, deviceId,
    expiresAt: "2026-10-08T22:29:59Z", operation: "register", priorBindingId: null,
    publicKey, requestId, schema: "hodlxxi.social_messaging_device_binding_record.v1",
    subject, validFrom: "2026-09-08T22:29:59Z", version: 1
  };
  vectors.push({
    claimType: "adoption", action: "adopt", requestId: "aa".repeat(32),
    digest: "c96902ddb67f6d63c1579e81100f267be27f5f0cd12727b521c76c66d8f25c36",
    eventId: "68bb9d6a6dc3a13630a47e27350be22859be407a0c2ff903a6820ab214d50955",
    signature: "70e3bc1a5609d946e607c8a63506ac3770889ae01b0c60721e88fa1228ba047f" +
      "1911f4a3a64aac0d60687df2a183cff1e33e7e64a6233a6708df4e16f9a6022f",
    envelope: { adoption: {
      action: "adopt", bindingId, bindingRecord, expiresAt: "2026-09-08T22:35:00Z",
      issuedAt: "2026-09-08T22:30:00Z", requestId: "aa".repeat(32),
      schema: "hodlxxi.social_messaging_device_binding_adoption.v1", version: 1
    }, domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_ADOPTION_V1" }
  });
  for (const vector of vectors) {
    const vectorContent = canonicalMessagingDeviceJson(vector.envelope);
    const vectorTags = [
      ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
      ["semantic-digest", vector.digest],
      ["request-id", vector.requestId],
      ["action", vector.action]
    ];
    const vectorToken = [
      b64({ alg: "RS256", kid: "service-key", typ: "hodlxxi-device-binding-intent+jwt" }),
      b64({
        iss: "https://identity.example", sub: subject, iat: 1788906600, exp: 1788906900,
        jti: vector.requestId,
        aud: "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1",
        tokenUse: "device_binding_authorization_intent",
        purpose: "social_messaging_device_binding_authorization_intent_v1",
        claimType: vector.claimType, action: vector.action, digest: vector.digest,
        eventId: vector.eventId, signatureFormat: "nostr_event_id_bip340_v1"
      }),
      "signature"
    ].join(".");
    const vectorIntent = {
      claim: vector.claimType === "lifecycle" ? vector.envelope.authorization : vector.envelope.adoption,
      claimType: vector.claimType, digest: vector.digest, expectedPubkey: subject,
      intentToken: vectorToken,
      schema: "hodlxxi.social_messaging_device_binding_authorization_intent.v1",
      signatureFormat: "nostr_event_id_bip340_v1",
      unsignedEvent: { content: vectorContent, created_at: 1788906600, kind: 27236, tags: vectorTags },
      version: 1
    };
    const parsed = await parseMessagingDeviceAuthorizationIntent(vectorIntent, {
      subject, cryptoImpl: webcrypto, now: () => 1_788_906_600_000
    });
    assert.equal(parsed.digest, vector.digest);
    assert.equal(parsed.eventId, vector.eventId);
    const payload = await composeMessagingDeviceAuthorizationPayload({
      subject,
      intentToken: vectorToken,
      signedEvent: {
        ...vectorIntent.unsignedEvent,
        id: vector.eventId,
        pubkey: subject,
        sig: vector.signature
      }
    }, { cryptoImpl: webcrypto, now: () => 1_788_906_600_000 });
    assert.equal(JSON.parse(payload).signature, vector.signature);
  }
});

test("valid wrong register rotate revoke and adoption intents are rejected before either signer", async () => {
  const registerProposal = {
    operation: "register", deviceId: "ff".repeat(32), publicKey,
    expectedBindingId: null, requestId
  };
  const priorBindingId = "6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d";
  const rotatedBindingId = "cc4efc97cef56180a86b1d9235b754fa717b45d4b9593ebdb04be4226c357b10";
  const base = {
    algorithm: "x25519-v1",
    bindingExpiresAt: "2026-10-08T22:29:59Z",
    bindingRecordSchema: "hodlxxi.social_messaging_device_binding_record.v1",
    bindingRecordVersion: 1,
    bindingValidFrom: "2026-09-08T22:30:00Z",
    deviceId,
    expiresAt: "2026-09-08T22:35:00Z",
    issuedAt: "2026-09-08T22:30:00Z",
    schema: "hodlxxi.social_messaging_device_binding_authorization.v1",
    subject,
    version: 1
  };
  const rotateRequestId = "44".repeat(32);
  const rotatePublicKey = "0a" + "00".repeat(31);
  const rotateIntent = fixedIntent({
    claimType: "lifecycle", action: "rotate", requestId: rotateRequestId,
    digest: "16c47dd55844cf3086124b87249ec395b7d42759215f14ccfa99259fa51dd80c",
    eventId: "a429b02a9223fcb463d64da2483fc8ec644d2002889cdc9fa29ba1ec72732f28",
    envelope: { authorization: { ...base, bindingVersion: 2, operation: "rotate",
      priorBindingId, publicKey: rotatePublicKey, requestId: rotateRequestId },
      domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1" }
  });
  const revokeRequestId = "55".repeat(32);
  const revokeIntent = fixedIntent({
    claimType: "lifecycle", action: "revoke", requestId: revokeRequestId,
    digest: "a7db4b3f77f902abfffe99ea33739b2c65f7a1ce2f0f313065e9f7bbdcdba8bb",
    eventId: "1da8e3972f9d82a15103a86de94ff06321e110065716baf5d3129a435063b2f6",
    envelope: { authorization: { ...base, bindingVersion: 3, operation: "revoke",
      priorBindingId: rotatedBindingId, publicKey: rotatePublicKey, requestId: revokeRequestId },
      domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1" }
  });
  const adoptionRequestId = "aa".repeat(32);
  const adoptionIntent = fixedIntent({
    claimType: "adoption", action: "adopt", requestId: adoptionRequestId,
    digest: "c96902ddb67f6d63c1579e81100f267be27f5f0cd12727b521c76c66d8f25c36",
    eventId: "68bb9d6a6dc3a13630a47e27350be22859be407a0c2ff903a6820ab214d50955",
    envelope: { adoption: {
      action: "adopt", bindingId: priorBindingId,
      bindingRecord: {
        algorithm: "x25519-v1", bindingVersion: 1, deviceId,
        expiresAt: "2026-10-08T22:29:59Z", operation: "register",
        priorBindingId: null, publicKey, requestId,
        schema: "hodlxxi.social_messaging_device_binding_record.v1", subject,
        validFrom: "2026-09-08T22:29:59Z", version: 1
      },
      expiresAt: "2026-09-08T22:35:00Z", issuedAt: "2026-09-08T22:30:00Z",
      requestId: adoptionRequestId,
      schema: "hodlxxi.social_messaging_device_binding_adoption.v1", version: 1
    }, domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_ADOPTION_V1" }
  });
  const cases = [
    ["register deviceId", intent(), registerProposal],
    ["register publicKey", intent(), {
      operation: "register", deviceId, publicKey: "0b" + "00".repeat(31),
      expectedBindingId: null, requestId
    }],
    ["register requestId", intent(), {
      operation: "register", deviceId, publicKey,
      expectedBindingId: null, requestId: "ab".repeat(32)
    }],
    ["rotate expectedBindingId", rotateIntent, {
      operation: "rotate", deviceId, publicKey: rotatePublicKey,
      expectedBindingId: "7".repeat(64), requestId: rotateRequestId
    }],
    ["rotate publicKey", rotateIntent, {
      operation: "rotate", deviceId, publicKey: "0c" + "00".repeat(31),
      expectedBindingId: priorBindingId, requestId: rotateRequestId
    }],
    ["revoke expectedBindingId", revokeIntent, {
      operation: "revoke", deviceId, publicKey: null,
      expectedBindingId: "8".repeat(64), requestId: revokeRequestId
    }],
    ["revoke deviceId", revokeIntent, {
      operation: "revoke", deviceId: "fe".repeat(32), publicKey: null,
      expectedBindingId: rotatedBindingId, requestId: revokeRequestId
    }],
    ["revoke requestId", revokeIntent, {
      operation: "revoke", deviceId, publicKey: null,
      expectedBindingId: rotatedBindingId, requestId: "bc".repeat(32)
    }],
    ["adopt bindingId", adoptionIntent, {
      operation: "adopt", bindingId: "9".repeat(64), requestId: adoptionRequestId
    }],
    ["adopt requestId", adoptionIntent, {
      operation: "adopt", bindingId: priorBindingId, requestId: "cd".repeat(32)
    }],
    ["cross-operation and action", revokeIntent, {
      operation: "rotate", deviceId, publicKey: rotatePublicKey,
      expectedBindingId: rotatedBindingId, requestId: revokeRequestId
    }]
  ];
  for (const [label, returnedIntent, proposal] of cases) {
    let nip07Reads = 0;
    let nip46Calls = 0;
    const guardedNip07 = {};
    Object.defineProperty(guardedNip07, "signEventForSubject", {
      get() { nip07Reads += 1; throw new Error("must not read signer"); }
    });
    for (const signer of [
      guardedNip07,
      createNip46MessagingDeviceSigner({
        publicKey: subject,
        request() { nip46Calls += 1; return Promise.resolve(signedEvent); },
        setTimer: () => 1,
        clearTimer() {}
      })
    ]) {
      await assert.rejects(authorizeMessagingDeviceBinding({ subject, proposal }, {
        signer,
        cryptoImpl: webcrypto,
        now: () => 1_788_906_600_000,
        persistPending: async () => { throw new Error("must not persist"); },
        fetchImpl: async () => response(returnedIntent)
      }), /authorization unavailable/, label);
    }
    assert.equal(nip07Reads, 0, label);
    assert.equal(nip46Calls, 0, label);
  }
});

test("signed public retry material persists before submit and retries exactly without resigning", async () => {
  const proposal = {
    operation: "register", deviceId, publicKey, expectedBindingId: null, requestId
  };
  let signatures = 0;
  let persisted;
  const firstCalls = [];
  await assert.rejects(authorizeMessagingDeviceBinding({ subject, proposal }, {
    signer: { async signEventForSubject() { signatures += 1; return signedEvent; } },
    cryptoImpl: webcrypto,
    now: vectorNow,
    async persistPending(value) {
      persisted = structuredClone(value);
      assert.deepEqual(firstCalls.map(([url]) => url), [
        "/auth/messaging-device-binding-authorization-intents"
      ]);
    },
    fetchImpl: async (url, init) => {
      firstCalls.push([url, init]);
      if (firstCalls.length === 1) return response(intent());
      throw new Error("ambiguous network failure");
    }
  }), /authorization unavailable/);
  assert.equal(signatures, 1);
  assert.equal(persisted.intentToken, intentToken);
  assert.deepEqual(persisted.signedEvent, signedEvent);

  let replacementSignerReads = 0;
  const forbiddenSigner = {};
  Object.defineProperty(forbiddenSigner, "signEventForSubject", {
    get() { replacementSignerReads += 1; throw new Error("must not read signer"); }
  });
  const retryCalls = [];
  const received = await authorizeMessagingDeviceBinding({
    subject, proposal, pendingAuthorization: persisted
  }, {
    signer: forbiddenSigner,
    cryptoImpl: webcrypto,
    now: vectorNow,
    fetchImpl: async (url, init) => {
      retryCalls.push([url, init]);
      return response(registerAuthorizationResult());
    }
  });
  assert.deepEqual(received, registerAuthorizationResult());
  assert.equal(replacementSignerReads, 0);
  assert.deepEqual(retryCalls.map(([url]) => url), [
    "/auth/messaging-device-binding-authorizations"
  ]);
  assert.equal(retryCalls[0][1].headers["X-HODLXXI-Device-Binding-Intent"], intentToken);
  assert.equal(retryCalls[0][1].body, canonicalMessagingDeviceJson(signedEvent));
});

test("expired cancelled subject-changed and tampered retry material never submits or signs", async () => {
  const proposal = {
    operation: "register", deviceId, publicKey, expectedBindingId: null, requestId
  };
  let persisted;
  const controller = new AbortController();
  await assert.rejects(authorizeMessagingDeviceBinding({ subject, proposal }, {
    signer: { async signEventForSubject() { return signedEvent; } },
    cryptoImpl: webcrypto,
    now: vectorNow,
    signal: controller.signal,
    async persistPending(value) { persisted = structuredClone(value); controller.abort(); },
    fetchImpl: async (_url, init) => response(init.body ===
      canonicalMessagingDeviceAuthorizationProposal(proposal) ? intent() : registerAuthorizationResult())
  }), /authorization unavailable/);
  let signerReads = 0;
  let submissions = 0;
  const signer = {};
  Object.defineProperty(signer, "signEventForSubject", {
    get() { signerReads += 1; throw new Error("must not read signer"); }
  });
  const rejectRetry = async (value, retrySubject = subject, retryNow = vectorNow) =>
    assert.rejects(authorizeMessagingDeviceBinding({
      subject: retrySubject, proposal, pendingAuthorization: value
    }, {
      signer,
      cryptoImpl: webcrypto,
      now: retryNow,
      fetchImpl: async () => { submissions += 1; return response(registerAuthorizationResult()); }
    }), /authorization unavailable/);
  await rejectRetry(persisted, subject, () => 1_788_906_899_000);
  await rejectRetry(persisted, "b".repeat(64));
  for (const mutate of [
    (value) => { value.intentToken = makeIntentToken({ eventId: "0".repeat(64) }); },
    (value) => { value.signedEvent.content += " "; },
    (value) => { value.proposal = value.proposal.replace(deviceId, "f".repeat(64)); }
  ]) {
    const value = structuredClone(persisted);
    mutate(value);
    await rejectRetry(value);
  }
  assert.equal(signerReads, 0);
  assert.equal(submissions, 0);
  await assert.rejects(parseMessagingDeviceAuthorizationRetry(
    { ...persisted, extra: true },
    { subject, proposal },
    vectorCrypto
  ), /authorization unavailable/);
});

test("NIP-07 rejection is generic and subject mismatch happens before signEvent lookup", async () => {
  const rejected = createNip07MessagingDeviceSigner({
    resolveProvider: () => ({ getPublicKey: async () => subject, signEvent: async () => { throw new Error("user detail"); } }),
    setTimer: () => 1,
    clearTimer() {}
  });
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent({ subject, intent: intent() }, { signer: rejected, ...vectorCrypto }),
    (error) => error.message === "messaging device authorization unavailable"
  );

  let signReads = 0;
  const provider = { getPublicKey: async () => "b".repeat(64) };
  Object.defineProperty(provider, "signEvent", {
    get() { signReads += 1; throw new Error("must not inspect"); }
  });
  const mismatch = createNip07MessagingDeviceSigner({
    resolveProvider: () => provider,
    setTimer: () => 1,
    clearTimer() {}
  });
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent({ subject, intent: intent() }, { signer: mismatch, ...vectorCrypto }),
    /authorization unavailable/
  );
  assert.equal(signReads, 0);
});

test("NIP-46 performs one exact one-shot sign_event request", async () => {
  const calls = [];
  const signer = createNip46MessagingDeviceSigner({
    publicKey: subject,
    request(value) { calls.push(value); return Promise.resolve(signedEvent); },
    setTimer: () => 1,
    clearTimer() {}
  });
  const result = await signMessagingDeviceAuthorizationIntent(
    { subject, intent: intent() }, { signer, ...vectorCrypto }
  );
  assert.equal(result.signedEvent.id, eventId);
  assert.deepEqual(calls, [{ method: "sign_event", params: [unsignedEvent] }]);
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent(
      { subject, intent: intent() }, { signer, ...vectorCrypto }
    ),
    /authorization unavailable/
  );
  assert.equal(calls.length, 1);
});

test("NIP-46 mismatch fails before transport and malformed result fails local verification", async () => {
  let calls = 0;
  const mismatch = createNip46MessagingDeviceSigner({
    publicKey: "b".repeat(64),
    request() { calls += 1; return Promise.resolve(signedEvent); }
  });
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent(
      { subject, intent: intent() }, { signer: mismatch, ...vectorCrypto }
    ),
    /authorization unavailable/
  );
  assert.equal(calls, 0);

  const malformed = createNip46MessagingDeviceSigner({
    publicKey: subject,
    request: () => Promise.resolve({ accepted: true })
  });
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent(
      { subject, intent: intent() }, { signer: malformed, ...vectorCrypto }
    ),
    /authorization unavailable/
  );
});

test("NIP-46 timeout and cancellation fail once without retry", { timeout: 10_000 }, async () => {
  let fire;
  let calls = 0;
  let resolveTimerInstalled;
  const timerInstalled = new Promise((resolve) => {
    resolveTimerInstalled = resolve;
  });
  const timed = createNip46MessagingDeviceSigner({
    publicKey: subject,
    request() { calls += 1; return new Promise(() => {}); },
    timeoutMs: 1,
    setTimer(callback) {
      fire = callback;
      resolveTimerInstalled();
      return 1;
    },
    clearTimer() {}
  });
  const pending = signMessagingDeviceAuthorizationIntent(
    { subject, intent: intent() }, { signer: timed, ...vectorCrypto }
  );
  await Promise.race([
    timerInstalled,
    pending.then(
      () => assert.fail("signing resolved before the timeout callback was installed"),
      (error) => assert.fail(
        `signing rejected before the timeout callback was installed: ${error.message}`
      )
    )
  ]);
  assert.equal(typeof fire, "function");
  fire();
  await assert.rejects(pending, /authorization unavailable/);
  assert.equal(calls, 1);

  const controller = new AbortController();
  controller.abort();
  const cancelled = createNip46MessagingDeviceSigner({
    publicKey: subject,
    signal: controller.signal,
    request() { calls += 1; return Promise.resolve(signedEvent); }
  });
  await assert.rejects(
    signMessagingDeviceAuthorizationIntent(
      { subject, intent: intent() }, { signer: cancelled, ...vectorCrypto }
    ),
    /authorization unavailable/
  );
  assert.equal(calls, 1);
});

test("carrier tampering fails for every trusted event component", async () => {
  const mutations = [
    (value) => { value.pubkey = "b".repeat(64); },
    (value) => { value.kind = 27235; },
    (value) => { value.created_at += 1; },
    (value) => { value.content += " "; },
    (value) => { value.tags[0][1] = "wrong"; },
    (value) => { value.tags.reverse(); },
    (value) => { value.tags[1][1] = "0".repeat(64); },
    (value) => { value.tags[2][1] = "4".repeat(64); },
    (value) => { value.tags[3][1] = "rotate"; },
    (value) => { value.id = "0".repeat(64); },
    (value) => { value.sig = "0".repeat(128); }
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(signedEvent);
    mutate(candidate);
    await assert.rejects(
      composeMessagingDeviceAuthorizationPayload(
        { subject, intentToken, signedEvent: candidate }, vectorCrypto
      ),
      /authorization unavailable/
    );
  }
});

test("intent token absence, mismatch, malformed intent, and old direct-style signature fail closed", async () => {
  for (const token of [undefined, "not-a-token", makeIntentToken({ eventId: "0".repeat(64) })]) {
    await assert.rejects(
      composeMessagingDeviceAuthorizationPayload(
        { subject, intentToken: token, signedEvent }, vectorCrypto
      ),
      /authorization unavailable/
    );
  }
  await assert.rejects(
    composeMessagingDeviceAuthorizationPayload(
      { subject, intentToken, signedEvent },
      { cryptoImpl: webcrypto, now: () => 1_788_906_899_000 }
    ),
    /authorization unavailable/
  );
  for (const mutate of [
    (value) => { value.digest = "0".repeat(64); },
    (value) => { value.unsignedEvent.tags[2][1] = "4".repeat(64); },
    (value) => { value.unsignedEvent.tags[3][1] = "rotate"; },
    (value) => { value.signatureFormat = "bip340_schnorr_sha256"; },
    (value) => { value.extra = true; }
  ]) {
    const value = intent(); mutate(value);
    await assert.rejects(
      parseMessagingDeviceAuthorizationIntent(value, { subject, ...vectorCrypto }),
      /authorization unavailable/
    );
  }
  await assert.rejects(
    composeMessagingDeviceAuthorizationPayload({
      subject, intentToken, signedEvent: { ...signedEvent, sig: "1".repeat(128) }
    }, vectorCrypto),
    /authorization unavailable/
  );
});

test("register rotate revoke and adoption proposals compose exactly", () => {
  const bindingId = "6".repeat(64);
  assert.equal(canonicalMessagingDeviceAuthorizationProposal({
    operation: "register", deviceId, publicKey, expectedBindingId: null, requestId
  }), JSON.stringify({ deviceId, expectedBindingId: null, operation: "register", publicKey, requestId }));
  assert.equal(canonicalMessagingDeviceAuthorizationProposal({
    operation: "rotate", deviceId, publicKey: "0a" + "00".repeat(31),
    expectedBindingId: bindingId, requestId: "44".repeat(32)
  }), JSON.stringify({ deviceId, expectedBindingId: bindingId, operation: "rotate",
    publicKey: "0a" + "00".repeat(31), requestId: "44".repeat(32) }));
  assert.equal(canonicalMessagingDeviceAuthorizationProposal({
    operation: "revoke", deviceId, publicKey: null,
    expectedBindingId: bindingId, requestId: "55".repeat(32)
  }), JSON.stringify({ deviceId, expectedBindingId: bindingId, operation: "revoke",
    publicKey: null, requestId: "55".repeat(32) }));
  assert.equal(canonicalMessagingDeviceAuthorizationProposal({
    operation: "adopt", bindingId, requestId: "aa".repeat(32)
  }), JSON.stringify({ bindingId, operation: "adopt", requestId: "aa".repeat(32) }));
});

test("browser composition uses only the two same-origin BFF calls and never publishes", async () => {
  const calls = [];
  const persisted = [];
  const result = {
    action: "register", active: true,
    authorizationExpiresAt: "2026-10-08T22:29:59Z",
    authorizationProofId: "hodlxxi-binding-authorization-v1-sha256:" + digest,
    authorizationValidFrom: "2026-09-08T22:29:59Z",
    bindingId: "6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d",
    bindingOperation: "register", bindingVersion: 1, deviceId,
    expiresAt: "2026-10-08T22:29:59Z", requestId,
    schema: "hodlxxi.social_messaging_device_binding_authorization_result.v1",
    validFrom: "2026-09-08T22:29:59Z", version: 1
  };
  const signer = { signEventForSubject: async () => signedEvent };
  const received = await authorizeMessagingDeviceBinding({
    subject,
    proposal: { operation: "register", deviceId, publicKey, expectedBindingId: null, requestId }
  }, {
    signer,
    cryptoImpl: webcrypto,
    now: vectorNow,
    async persistPending(value) {
      persisted.push(structuredClone(value));
      assert.equal(calls.length, 1);
    },
    fetchImpl: async (url, init) => {
      calls.push([url, init]);
      return response(calls.length === 1 ? intent() : result);
    }
  });
  assert.deepEqual(received, result);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].intentToken, intentToken);
  assert.deepEqual(persisted[0].signedEvent, signedEvent);
  assert.deepEqual(calls.map(([url]) => url), [
    "/auth/messaging-device-binding-authorization-intents",
    "/auth/messaging-device-binding-authorizations"
  ]);
  assert.equal(calls[1][1].headers["X-HODLXXI-Device-Binding-Intent"], intentToken);
  assert.deepEqual(JSON.parse(calls[1][1].body), signedEvent);
  const source = await readFile(new URL("../web/messaging-device-authorization-v1.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /WebSocket|\["EVENT"|publish|relayUrl|localStorage|sessionStorage|privateKey/i);
  const nip46Source = await readFile(new URL("../web/nip46-messaging-device-signer-v1.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(nip46Source, /WebSocket|publish|relayUrl|localStorage|sessionStorage|privateKey|setInterval|retry/i);

  for (const field of [
    "action", "active", "authorizationExpiresAt", "authorizationProofId",
    "authorizationValidFrom", "bindingId", "bindingOperation", "bindingVersion",
    "deviceId", "expiresAt", "requestId", "validFrom"
  ]) {
    const tampered = structuredClone(result);
    tampered[field] = field === "active" ? false : field === "bindingVersion" ? 2 : "0".repeat(64);
    await assert.rejects(
      authorizeMessagingDeviceBinding({
        subject,
        proposal: { operation: "register", deviceId, publicKey, expectedBindingId: null, requestId }
      }, {
        signer,
        cryptoImpl: webcrypto,
        now: vectorNow,
        persistPending: async () => {},
        fetchImpl: async (_url, init) => response(init.body === canonicalMessagingDeviceJson({
          deviceId, expectedBindingId: null, operation: "register", publicKey, requestId
        }) ? intent() : tampered)
      }),
      /authorization unavailable/,
      field
    );
  }
});
