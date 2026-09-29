import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as contract from "../web/mobile-device-authorization-contract-v2.mjs";

const fixtureBytes = await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
  import.meta.url
));
const fixture = JSON.parse(fixtureBytes);
const vector = fixture.vector;
const pre = JSON.parse(vector.preEnrollmentWire);
const outer = JSON.parse(vector.authorizationWire);
const event = JSON.parse(vector.approvalEventWire);
const secret = "77".repeat(32);
const verifier = "88".repeat(32);
const proposal = Object.freeze({
  deviceId: pre.deviceId,
  expectedBindingId: null,
  operation: "register",
  publicKey: "09" + "00".repeat(31),
  requestId: pre.requestId
});
const options = Object.freeze({
  subject: pre.subject,
  proposal,
  cryptoImpl: webcrypto
});
const unavailable = {
  name: "TypeError",
  message: "mobile device authorization v2 unavailable"
};

const sorted = (value) => {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sorted(value[key])])
    );
  }
  return value;
};
const canonical = (value) => JSON.stringify(sorted(value));
const changed = (source, changes) => canonical({ ...JSON.parse(source), ...changes });

test("authoritative 32,998-byte fixture and public-only contents are frozen", () => {
  assert.equal(fixtureBytes.byteLength, 32_998);
  assert.equal(
    createHash("sha256").update(fixtureBytes).digest("hex"),
    "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc"
  );
  assert.equal(fixture.schema,
    "hodlxxi.social_preacceptance_ed25519_handoff_fixture.v2");
  for (const forbidden of [
    "privateKey", "private_key", "pairingSecret", "rawPairingSecret", "seed"
  ]) assert.equal(fixtureBytes.includes(Buffer.from(forbidden)), false);
});

test("all deterministic pre-enrollment, outer, event and acceptance bytes reconstruct", async () => {
  const preWire = contract.createPreEnrollmentV2({
    bindingAuthorizationDigest: pre.bindingAuthorizationDigest,
    deviceId: pre.deviceId,
    ed25519PublicKey: pre.ed25519PublicKey,
    expiresAt: pre.expiresAt,
    issuedAt: pre.issuedAt,
    pairingId: pre.pairingId,
    requestId: pre.requestId,
    subject: pre.subject,
    x25519BindingId: pre.x25519BindingId,
    x25519BindingVersion: pre.x25519BindingVersion,
    x25519PublicKeyCommitment: pre.x25519PublicKeyCommitment
  });
  assert.equal(preWire, vector.preEnrollmentWire);
  assert.equal(await contract.preEnrollmentDigestV2(preWire, webcrypto),
    vector.preEnrollmentDigest);
  const bound = await contract.createBoundPreEnrollmentV2({
    content: outer.content,
    ed25519PublicKey: pre.ed25519PublicKey,
    expiresAt: pre.expiresAt,
    pairingId: pre.pairingId
  }, options);
  assert.equal(bound, preWire);
  const outerWire = await contract.createAuthorizationEnvelopeV2({
    content: outer.content,
    contextWire: canonical(outer.context),
    preEnrollmentWire: preWire
  }, options);
  assert.equal(outerWire, vector.authorizationWire);
  assert.equal(await contract.authorizationDigestV2(outerWire, options),
    vector.authorizationDigest);
  assert.equal(await contract.approvalEventIdInputV2(outerWire, options),
    vector.approvalEventIdInput);
  assert.equal(await contract.approvalEventIdV2(outerWire, options),
    vector.approvalEventId);
  assert.equal(await contract.createApprovalEventV2(
    outerWire,
    vector.approvalEventSignature,
    options
  ), vector.approvalEventWire);
  const approval = await contract.parseApprovalEventV2(
    vector.approvalEventWire,
    options
  );
  assert.equal(approval.eventId, vector.approvalEventId);
  assert.equal(await contract.acceptanceIdPreimageV2(approval.wire, options),
    vector.acceptanceIdPreimage);
  assert.equal(await contract.acceptanceIdV2(approval.wire, options),
    vector.acceptanceId);
  assert.equal(await contract.createAcceptanceV2(
    approval.wire,
    pre.issuedAt,
    options
  ), vector.acceptanceWire);
  assert.equal((await contract.parseAcceptanceV2(
    vector.acceptanceWire,
    approval.wire,
    options
  )).acceptanceId, vector.acceptanceId);
});

test("V2 commitments, HMAC proof and every acceptance clock are exact", async () => {
  assert.equal(await contract.pairingSecretCommitmentV2(secret, webcrypto),
    outer.context.secretCommitment);
  assert.equal(await contract.phoneExchangeCommitmentV2(verifier, webcrypto),
    outer.context.exchangeCommitment);
  assert.equal(await contract.pairingPossessionProofV2(
    secret,
    vector.authorizationDigest,
    webcrypto
  ), vector.pairingPossessionProof);
  const valid = await contract.validateAuthorizationTimeV2(
    vector.authorizationWire,
    pre.issuedAt,
    options
  );
  assert.equal(valid.preEnrollment.pairingId, pre.pairingId);
  assert.equal((await contract.verifyPairingPossessionV2(
    vector.authorizationWire,
    {
      ...options,
      nowMs: pre.issuedAt,
      possessionProof: vector.pairingPossessionProof,
      secret
    }
  )).preEnrollment.pairingId, pre.pairingId);
  await assert.rejects(contract.verifyPairingPossessionV2(
    vector.authorizationWire,
    {
      ...options,
      nowMs: pre.issuedAt,
      possessionProof: "00".repeat(32),
      secret
    }
  ), unavailable);
  await assert.rejects(contract.validateAuthorizationTimeV2(
    vector.authorizationWire,
    pre.issuedAt - 1,
    options
  ), unavailable);
  await assert.rejects(contract.validateAuthorizationTimeV2(
    vector.authorizationWire,
    Date.parse(outer.context.expiresAt),
    options
  ), unavailable);
});

test("immutable signed-attempt bytes reparse and disclose no secret or private material", async () => {
  const wire = await contract.createSignedAttemptV2(
    vector.authorizationWire,
    event,
    options
  );
  const parsed = await contract.parseSignedAttemptV2(wire, options);
  assert.equal(parsed.approval.eventId, vector.approvalEventId);
  const value = JSON.parse(wire);
  assert.equal(value.authorizationWire, vector.authorizationWire);
  assert.equal(value.approvalEventWire, vector.approvalEventWire);
  assert.equal(value.approvalEventId, vector.approvalEventId);
  assert.equal(value.approvalEventSignature, vector.approvalEventSignature);
  assert.equal(value.requestId, pre.requestId);
  assert.equal(value.pairingId, pre.pairingId);
  for (const forbidden of [secret, "privateKey", "private_key", "seed"]) {
    assert.equal(wire.includes(forbidden), false);
  }
  await assert.rejects(contract.parseSignedAttemptV2(
    changed(wire, { approvalEventId: "00".repeat(32) }),
    options
  ), unavailable);
});

test("every approval-event field is independently reparsed and BIP340 verified", async () => {
  const replacements = {
    content: vector.authorizationWire + " ",
    created_at: event.created_at + 1,
    id: "00".repeat(32),
    kind: 27_235,
    pubkey: "11".repeat(32),
    sig: "00".repeat(64),
    tags: [...event.tags].reverse()
  };
  for (const field of Object.keys(replacements)) {
    await assert.rejects(contract.parseApprovalEventV2(
      canonical({ ...event, [field]: replacements[field] }),
      options
    ), unavailable, field);
  }
});

test("register + initial is exclusive and V1/V2 substitutions fail closed", async () => {
  for (const [field, value] of [
    ["transitionKind", "rotate"],
    ["transitionKind", "reenroll"],
    ["preEffectAssociationState", "active"],
    ["preEffectAssociationId", "11".repeat(32)],
    ["preEffectAssociationVersion", 1],
    ["preEffectAuthorityEpoch", 1],
    ["proposedAssociationVersion", 2],
    ["proposedAuthorityEpoch", 2],
    ["proposedPredecessorAssociationId", "11".repeat(32)]
  ]) {
    assert.throws(() => contract.parsePreEnrollmentV2(
      changed(vector.preEnrollmentWire, { [field]: value })
    ), unavailable, field);
  }
  for (const [field, value] of [
    ["method", "qr_desktop_v1"],
    ["schema", "hodlxxi.social_messaging_device_authorization_method.v1"],
    ["domain", "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V1"],
    ["version", 1]
  ]) {
    await assert.rejects(contract.parseAuthorizationEnvelopeV2(
      canonical({ ...outer, [field]: value }),
      options
    ), unavailable, field);
  }
  const v1 = JSON.parse(await readFile(new URL(
    "./fixtures/social_mobile_device_authorization_v1.json",
    import.meta.url
  )));
  await assert.rejects(contract.parseAuthorizationEnvelopeV2(
    v1.entries[0].qr_desktop_v1.content,
    options
  ), unavailable);
});

test("closed canonical parsers reject limits, duplicates, escapes, non-ASCII and unsafe numbers", async () => {
  for (const malformed of [
    " " + vector.preEnrollmentWire,
    vector.preEnrollmentWire + " ",
    vector.preEnrollmentWire.replace('"initial"', '"\\u0069nitial"'),
    vector.preEnrollmentWire.slice(0, -1) + ',"version":2}',
    vector.preEnrollmentWire + "é",
    changed(vector.preEnrollmentWire, { issuedAt: 9_007_199_254_740_992 }),
    "{" + '"x":'.repeat(8_193) + "0" + "}".repeat(8_193)
  ]) {
    assert.throws(() => contract.parsePreEnrollmentV2(malformed), unavailable);
  }
  const inherited = Object.create({ content: outer.content });
  Object.assign(inherited, {
    contextWire: canonical(outer.context),
    preEnrollmentWire: vector.preEnrollmentWire
  });
  await assert.rejects(contract.createAuthorizationEnvelopeV2(
    inherited,
    options
  ), unavailable);
  const accessor = {};
  Object.defineProperty(accessor, "content", { enumerable: true, get() { return outer.content; } });
  Object.assign(accessor, {
    contextWire: canonical(outer.context),
    preEnrollmentWire: vector.preEnrollmentWire
  });
  await assert.rejects(contract.createAuthorizationEnvelopeV2(accessor, options),
    unavailable);

  const nestedContext = canonical({
    ...outer,
    context: { ...outer.context, createdAt: { nested: outer.context.createdAt } }
  });
  await assert.rejects(contract.parseAuthorizationEnvelopeV2(
    nestedContext,
    options
  ), unavailable);
  await assert.rejects(contract.parseApprovalEventV2(canonical({
    ...event,
    tags: [["purpose", ["nested"]], ...event.tags.slice(1)]
  }), options), unavailable);
  assert.throws(() => contract.parsePreEnrollmentV2("x".repeat(8_193)),
    unavailable);
});

test("approval tags reject non-ordinary arrays, inherited/own hooks, accessors and oversized shapes", async () => {
  const cloneTags = () => event.tags.map((tag) => [...tag]);
  const malformed = [];

  const customOuter = cloneTags();
  Object.setPrototypeOf(customOuter, { map: Array.prototype.map });
  malformed.push(customOuter);

  const customInner = cloneTags();
  Object.setPrototypeOf(customInner[0], {
    private_key: "secret",
    seed: "secret",
    [Symbol.iterator]: Array.prototype[Symbol.iterator]
  });
  malformed.push(customInner);

  for (const property of ["map", "private_key", "seed", Symbol.iterator]) {
    const tags = cloneTags();
    Object.defineProperty(tags, property, {
      configurable: true,
      value: property === Symbol.iterator
        ? Array.prototype[Symbol.iterator] : "secret"
    });
    malformed.push(tags);
  }

  const accessor = cloneTags();
  Object.defineProperty(accessor[0], "1", {
    enumerable: true,
    get() { throw new Error("tag getter secret"); }
  });
  malformed.push(accessor);

  const oversizedOuter = [];
  oversizedOuter.length = 1_000_000_000;
  malformed.push(oversizedOuter);
  const oversizedInner = cloneTags();
  oversizedInner[0] = [];
  oversizedInner[0].length = 1_000_000_000;
  malformed.push(oversizedInner);

  for (const tags of malformed) {
    await assert.rejects(contract.createSignedAttemptV2(
      vector.authorizationWire,
      { ...event, tags },
      options
    ), unavailable);
  }
});

test("every public function uniformly redacts malformed, accessor and crypto failures", async () => {
  const secret = "sentinel-secret-must-not-escape";
  const poison = new Proxy({}, {
    getPrototypeOf() { return Object.prototype; },
    ownKeys() { throw new Error(secret); }
  });
  const poisonOptions = new Proxy({}, {
    get() { throw new Error(secret); }
  });
  const poisonCrypto = new Proxy({}, {
    get() { throw new Error(secret); }
  });
  const signedAttemptWire = await contract.createSignedAttemptV2(
    vector.authorizationWire,
    event,
    options
  );
  const cases = {
    acceptanceIdPreimageV2: () => contract.acceptanceIdPreimageV2(
      vector.approvalEventWire, poisonOptions
    ),
    acceptanceIdV2: () => contract.acceptanceIdV2(
      vector.approvalEventWire, poisonOptions
    ),
    approvalEventIdInputV2: () => contract.approvalEventIdInputV2(
      vector.authorizationWire, poisonOptions
    ),
    approvalEventIdV2: () => contract.approvalEventIdV2(
      vector.authorizationWire, poisonOptions
    ),
    approvalUnsignedEventV2: () => contract.approvalUnsignedEventV2(
      vector.authorizationWire, poisonOptions
    ),
    authorizationDigestV2: () => contract.authorizationDigestV2(
      vector.authorizationWire, poisonOptions
    ),
    createAcceptanceV2: () => contract.createAcceptanceV2(
      vector.approvalEventWire, pre.issuedAt, poisonOptions
    ),
    createApprovalEventV2: () => contract.createApprovalEventV2(
      vector.authorizationWire, vector.approvalEventSignature, poisonOptions
    ),
    createAuthorizationEnvelopeV2: () =>
      contract.createAuthorizationEnvelopeV2(poison, options),
    createBoundPreEnrollmentV2: () =>
      contract.createBoundPreEnrollmentV2(poison, options),
    createPreEnrollmentV2: () => contract.createPreEnrollmentV2(poison),
    createSignedAttemptV2: () => contract.createSignedAttemptV2(
      vector.authorizationWire, event, poisonOptions
    ),
    pairingPossessionProofV2: () => contract.pairingPossessionProofV2(
      secret.slice(0, 0) + "77".repeat(32),
      vector.authorizationDigest,
      poisonCrypto
    ),
    pairingSecretCommitmentV2: () => contract.pairingSecretCommitmentV2(
      "77".repeat(32), poisonCrypto
    ),
    parseAcceptanceV2: () => contract.parseAcceptanceV2(
      vector.acceptanceWire, vector.approvalEventWire, poisonOptions
    ),
    parseApprovalEventV2: () => contract.parseApprovalEventV2(
      vector.approvalEventWire, poisonOptions
    ),
    parseAuthorizationEnvelopeV2: () => contract.parseAuthorizationEnvelopeV2(
      vector.authorizationWire, poisonOptions
    ),
    parsePreEnrollmentV2: () => contract.parsePreEnrollmentV2(secret),
    parseSignedAttemptV2: () => contract.parseSignedAttemptV2(
      signedAttemptWire, poisonOptions
    ),
    phoneExchangeCommitmentV2: () => contract.phoneExchangeCommitmentV2(
      "88".repeat(32), poisonCrypto
    ),
    preEnrollmentDigestV2: () => contract.preEnrollmentDigestV2(
      vector.preEnrollmentWire, poisonCrypto
    ),
    validateAuthorizationTimeV2: () => contract.validateAuthorizationTimeV2(
      vector.authorizationWire, pre.issuedAt, poisonOptions
    ),
    verifyPairingPossessionV2: () => contract.verifyPairingPossessionV2(
      vector.authorizationWire,
      {
        cryptoImpl: poisonCrypto,
        nowMs: pre.issuedAt,
        possessionProof: vector.pairingPossessionProof,
        proposal,
        secret: "77".repeat(32),
        subject: pre.subject
      }
    )
  };
  assert.deepEqual(
    Object.keys(cases).sort(),
    Object.entries(contract)
      .filter(([, value]) => typeof value === "function")
      .map(([name]) => name)
      .sort()
  );
  for (const [name, invoke] of Object.entries(cases)) {
    let error;
    try {
      await invoke();
    } catch (caught) {
      error = caught;
    }
    assert.equal(error?.constructor, TypeError, name);
    assert.equal(error?.message,
      "mobile device authorization v2 unavailable", name);
    assert.equal(String(error).includes(secret), false, name);
    assert.equal(Object.hasOwn(error, "cause"), false, name);
  }
  let wholeArgumentError;
  try {
    await contract.verifyPairingPossessionV2(
      vector.authorizationWire,
      poison
    );
  } catch (caught) {
    wholeArgumentError = caught;
  }
  assert.equal(wholeArgumentError?.constructor, TypeError);
  assert.equal(wholeArgumentError?.message,
    "mobile device authorization v2 unavailable");
  assert.equal(String(wholeArgumentError).includes(secret), false);
  assert.equal(Object.hasOwn(wholeArgumentError, "cause"), false);
});

test("module remains dormant and provides no publish, transport or authority API", async () => {
  assert.equal(contract.MOBILE_DEVICE_AUTHORIZATION_V2_RUNTIME_ENABLED, false);
  const source = await readFile(new URL(
    "../web/mobile-device-authorization-contract-v2.mjs",
    import.meta.url
  ), "utf8");
  assert.doesNotMatch(source,
    /fetch\(|XMLHttpRequest|WebSocket|\.publish\b|relay|localStorage|sessionStorage/);
  assert.doesNotMatch(source, /privateKey|pairingSecret\s*:/);
});
