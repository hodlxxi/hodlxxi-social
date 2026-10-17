import assert from "node:assert/strict";
import {
  createHash, createPublicKey, generateKeyPairSync, sign, verify
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2 as createSigner,
  produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2 as produce,
  PREACCEPTED_ENROLLMENT_FRESHNESS_NATIVE_60S_V1 as NATIVE,
  MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_LIFETIME_MS as LEGACY_MAX
} from "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs";

const statement = JSON.parse(await readFile(new URL(
  "./fixtures/social_preaccepted_enrollment_verification_statement_v2.json",
  import.meta.url
)));
const source = JSON.parse(await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json", import.meta.url
)));
const { configuration: config, deadlines, vector } = statement;
const enabled = { preacceptedEnrollmentVerificationStatementsV2Enabled: true };
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const canonical = (value) => JSON.stringify(Object.fromEntries(
  Object.keys(value).sort().map((key) => [key, value[key]])
));
const denied = { message: "messaging device preaccepted enrollment verification statement v2 unavailable" };

function metadata(signExact = (bytes) => sign("RSA-SHA256", bytes, privateKey)) {
  return {
    algorithm: "RS256", audience: config.audience, clientId: config.clientId,
    issuer: config.issuer, kid: config.kid,
    purpose: "social_preaccepted_enrollment_cryptographic_verification_v2",
    servicePrincipal: config.servicePrincipal, signExact
  };
}

function input(signer, changes = {}) {
  return {
    approverSessionExpiresAtMs: deadlines.approverSessionExpiresAtMs,
    contextWire: source.vector.verificationContextWire,
    expectedAlgorithm: "RS256", expectedAudience: config.audience,
    expectedClientId: config.clientId, expectedIssuer: config.issuer,
    expectedKid: config.kid,
    expectedPurpose: "social_preaccepted_enrollment_cryptographic_verification_v2",
    expectedServicePrincipal: config.servicePrincipal,
    fullExpiresAtMs: deadlines.fullExpiresAtMs,
    inputWire: source.vector.preacceptedEnrollmentVerificationInputWire,
    now: deadlines.now, phoneSessionExpiresAtMs: deadlines.phoneSessionExpiresAtMs,
    signer, statementLifetimeMs: 9000,
    x25519BindingExpiresAtMs: deadlines.x25519BindingExpiresAtMs, ...changes
  };
}

function authenticatedPayload(compact) {
  const [header, payload, signature] = compact.split(".");
  assert.equal(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`, "ascii"),
    publicKey, Buffer.from(signature, "base64url")), true);
  return Buffer.from(payload, "base64url").toString("ascii");
}

test("default and explicit legacy signers reproduce the unchanged public vector", async () => {
  assert.equal(LEGACY_MAX, 10_000);
  for (const options of [undefined, { freshnessProfile: "legacy-10s" }]) {
    const signer = createSigner(metadata(() => Buffer.from(vector.signature, "base64url")), options);
    const compact = await produce(input(signer), enabled);
    assert.equal(compact, vector.compactJws);
    const [header, payload, signature] = compact.split(".");
    const fixtureKey = createPublicKey({ key: statement.publicVerificationMaterial.jwk, format: "jwk" });
    assert.equal(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`, "ascii"),
      fixtureKey, Buffer.from(signature, "base64url")), true);
    assert.equal(Object.hasOwn(JSON.parse(Buffer.from(payload, "base64url")), "freshnessProfile"), false);
  }
});

for (const lifetime of [1, 9000, 10_000, 10_001, 60_000]) {
  test(`explicit native profile signs exact marker and JTI at ${lifetime} ms`, async () => {
    const signer = createSigner(metadata(), { freshnessProfile: NATIVE });
    const compact = await produce(input(signer, { statementLifetimeMs: lifetime }), enabled);
    const expected = JSON.parse(vector.payloadWithoutJtiWire);
    expected.expiresAt = deadlines.now + lifetime;
    expected.freshnessProfile = NATIVE;
    const withoutJti = canonical(expected);
    expected.jti = createHash("sha256").update(
      "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2\0" + withoutJti,
      "ascii"
    ).digest("hex");
    assert.equal(authenticatedPayload(compact), canonical(expected));
  });
}

test("overlong intervals deny before the signer for each server-selected profile", async () => {
  let calls = 0;
  for (const [profile, maximum] of [["legacy-10s", 10_000], [NATIVE, 60_000]]) {
    const signer = createSigner(metadata(() => { calls += 1; return Buffer.alloc(256); }),
      { freshnessProfile: profile });
    for (const lifetime of [maximum + 1, 0, -1, 1.5, "9000", true]) {
      await assert.rejects(produce(input(signer, { statementLifetimeMs: lifetime }), enabled), denied);
    }
  }
  assert.equal(calls, 0);
});

test("unknown, boxed, missing and accessor profile configuration denies", () => {
  for (const value of ["native-v2-600s-v1", "", true, 60_000, null, new String(NATIVE)]) {
    assert.throws(() => createSigner(metadata(), { freshnessProfile: value }), denied);
  }
  for (const options of [null, {}, [], { freshnessProfile: NATIVE, extra: true },
    Object.create({ freshnessProfile: NATIVE }), new Proxy({ freshnessProfile: NATIVE }, {})]) {
    assert.throws(() => createSigner(metadata(), options), denied);
  }
  let getters = 0;
  assert.throws(() => createSigner(metadata(), {
    get freshnessProfile() { getters += 1; return NATIVE; }
  }), denied);
  assert.equal(getters, 0);
});

test("profile snapshot belongs to the signer and request bytes cannot select it", async () => {
  let calls = 0;
  const options = { freshnessProfile: NATIVE };
  const signer = createSigner(metadata((bytes) => { calls += 1; return sign("RSA-SHA256", bytes, privateKey); }), options);
  options.freshnessProfile = "legacy-10s";
  assert.equal(JSON.parse(authenticatedPayload(await produce(
    input(signer, { statementLifetimeMs: 60_000 }), enabled
  ))).freshnessProfile, NATIVE);
  const before = calls;
  await assert.rejects(produce(input(signer, { freshnessProfile: NATIVE }), enabled), denied);
  await assert.rejects(produce(input(signer), { ...enabled, freshnessProfile: NATIVE }), denied);
  assert.equal(calls, before);
  assert.equal(Object.hasOwn(signer, "freshnessProfile"), false);
});

test("native profile preserves independent exclusive deadlines", async () => {
  let calls = 0;
  const signer = createSigner(metadata(() => { calls += 1; return Buffer.alloc(256); }),
    { freshnessProfile: NATIVE });
  for (const field of ["phoneSessionExpiresAtMs", "approverSessionExpiresAtMs", "fullExpiresAtMs"]) {
    await assert.rejects(produce(input(signer, {
      statementLifetimeMs: 60_000, [field]: deadlines.now + 59_999
    }), enabled), denied);
    await assert.rejects(produce(input(signer, {
      statementLifetimeMs: 1, [field]: deadlines.now
    }), enabled), denied);
  }
  await assert.rejects(produce(input(signer, {
    statementLifetimeMs: 1, now: JSON.parse(source.vector.enrollmentWire).expiresAt
  }), enabled), denied);
  await assert.rejects(produce(input(signer, {
    statementLifetimeMs: 60_000, x25519BindingExpiresAtMs: deadlines.x25519BindingExpiresAtMs - 1
  }), enabled), denied);
  assert.equal(calls, 0);
});

test("the longer profile keeps the enable gate and genuine phone verification", async () => {
  let calls = 0;
  const signer = createSigner(metadata(() => { calls += 1; return Buffer.alloc(256); }),
    { freshnessProfile: NATIVE });
  await assert.rejects(produce(input(signer)), denied);
  const forged = JSON.parse(source.vector.preacceptedEnrollmentVerificationInputWire);
  const proof = JSON.parse(forged.phoneProof);
  proof.signature = "00".repeat(64);
  forged.phoneProof = canonical(proof);
  await assert.rejects(produce(input(signer, { inputWire: canonical(forged) }), enabled), denied);
  assert.equal(calls, 0);
});
