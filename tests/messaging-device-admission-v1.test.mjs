import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  APPROVED_DEVICE_PROOF_PROFILE, DEVICE_ADMISSION_ENABLED,
  admitMessagingDeviceRequestV1, createDeviceRequestCandidateV1,
  parseDeviceRequestCandidateV1, createDeviceChallengeCandidateV1,
  inspectDeviceChallengeCandidateV1, digestDeviceChallengeCandidateV1
} from "../src/server/messaging-device-admission-v1.mjs";
import { createMessageRoutingRequestV1 } from "../src/server/message-routing-request-v1.mjs";

const bytes = await readFile(new URL("./fixtures/social_messaging_device_admission_v1.json", import.meta.url));
const { vectors } = JSON.parse(bytes);
const routing = JSON.parse(await readFile(new URL("./fixtures/social_messaging_phase3_routing_v1.json", import.meta.url)));
const on = { enabled: true };
const error = { name: "TypeError", message: "messaging device admission unavailable" };
const denied = (fn) => assert.throws(fn, error);
const canonical = (v) => JSON.stringify(v, Object.keys(v).sort());
const change = (wire, changes) => canonical({ ...JSON.parse(wire), ...changes });
const build = (v, context = v.contextWire, body = v.bodyWire, method = v.method, path = v.path, options = on) =>
  createDeviceRequestCandidateV1(context, v.operation, method, path, body, options);
const inspect = (v, actual = v.requestWire, now = JSON.parse(v.challengeWire).issuedAt, options = on) =>
  inspectDeviceChallengeCandidateV1(v.challengeWire, actual, now, options);

test("independent canonical vectors stay frozen", () => {
  assert.equal(createHash("sha256").update(bytes).digest("hex"), "9456c9d70dc4f0db4a417a330a94d969fd0be49bf75e2e9b797a6b3a9dd3d6b7");
  for (const v of vectors) {
    assert.equal(build(v), v.requestWire);
    assert.equal(Buffer.byteLength(v.requestWire), v.requestBytes);
    const c = JSON.parse(v.challengeWire);
    assert.equal(createDeviceChallengeCandidateV1(v.requestWire, c.challengeId, c.issuedAt, c.expiresAt, on), v.challengeWire);
    assert.equal(Buffer.byteLength(v.challengeWire), v.challengeBytes);
    assert.equal(digestDeviceChallengeCandidateV1(v.challengeWire, on), v.challengeDigest);
    assert.ok(Object.isFrozen(inspect(v)));
    assert.ok(Object.isFrozen(parseDeviceRequestCandidateV1(v.requestWire, on)));
    denied(() => admitMessagingDeviceRequestV1({ challenge: inspect(v) }, on));
  }
});

test("real merged envelope producer/consumer compatibility and all routing bytes remain unchanged", () => {
  assert.equal(vectors[0].bodyWire, routing.envelopeWire);
  assert.equal(createMessageRoutingRequestV1(vectors[0].bodyWire, on), routing.routingRequest);
  const req = JSON.parse(vectors[0].requestWire);
  assert.notEqual(req.bodyDigest, routing.envelopeDigest);
  for (const field of ["subject", "bindingId", "deviceId", "sessionBinding"]) {
    assert.ok(!routing.routingRequest.includes(req[field]));
  }
  assert.equal(JSON.parse(vectors[1].bodyWire).deviceHandle, routing.recipientPackage.devices[0].deviceHandle);
});

test("every candidate helper defaults off and rejects inherited/accessor/proxy/truthy enablement", () => {
  const v = vectors[0], c = JSON.parse(v.challengeWire);
  const helpers = [
    (o) => build(v, v.contextWire, v.bodyWire, v.method, v.path, o),
    (o) => parseDeviceRequestCandidateV1(v.requestWire, o),
    (o) => createDeviceChallengeCandidateV1(v.requestWire, c.challengeId, c.issuedAt, c.expiresAt, o),
    (o) => inspectDeviceChallengeCandidateV1(v.challengeWire, v.requestWire, c.issuedAt, o),
    (o) => digestDeviceChallengeCandidateV1(v.challengeWire, o)
  ];
  const accessor = { get enabled() { assert.fail("accessor ran"); } };
  const proxy = new Proxy(on, { getOwnPropertyDescriptor() { assert.fail("proxy ran"); } });
  for (const helper of helpers) {
    for (const options of [{}, null, true, { enabled: false }, { enabled: 1 }, { enabled: "true" },
      Object.create(on), accessor, proxy]) denied(() => helper(options));
  }
  // Explicit omitted arguments, including build's own convenience default.
  denied(() => createDeviceRequestCandidateV1(v.contextWire, v.operation, v.method, v.path, v.bodyWire));
  denied(() => parseDeviceRequestCandidateV1(v.requestWire));
  denied(() => createDeviceChallengeCandidateV1(v.requestWire, c.challengeId, c.issuedAt, c.expiresAt));
  denied(() => inspectDeviceChallengeCandidateV1(v.challengeWire, v.requestWire, c.issuedAt));
  denied(() => digestDeviceChallengeCandidateV1(v.challengeWire));
});

for (const v of vectors) {
  test(`${v.operation}: exact subject, session generation, device, binding, version, audience and path`, () => {
    for (const changes of [{ subject: "aa".repeat(32) }, { sessionBinding: "bb".repeat(32) },
      { deviceId: "cc".repeat(32) }, { bindingId: "dd".repeat(32) }, { bindingVersion: 2 },
      { audience: "https://another.example" }]) {
      const actual = build(v, change(v.contextWire, changes));
      denied(() => inspect(v, actual));
    }
    denied(() => inspect(v, build(v, v.contextWire, v.bodyWire, "POST", v.path + "/other")));
    for (const method of ["GET", "post", "PUT", "POST ", null, {}]) {
      denied(() => build(v, v.contextWire, v.bodyWire, method));
      denied(() => inspect(v, change(v.requestWire, { method })));
    }
    for (const path of [v.path + "?a=1", v.path + "#x", v.path + "/", "/a/../b", "/%61", "//auth", "/" + "a".repeat(160), "https://social.example" + v.path]) {
      denied(() => build(v, v.contextWire, v.bodyWire, "POST", path));
    }
  });

  test(`${v.operation}: exact exclusive freshness without clock skew`, () => {
    const c = JSON.parse(v.challengeWire);
    inspect(v, v.requestWire, c.issuedAt);
    inspect(v, v.requestWire, c.expiresAt - 1);
    for (const now of [c.issuedAt - 1, c.expiresAt, c.expiresAt + 1, -1, NaN, Infinity, "1788906599000", 1.5, true]) {
      denied(() => inspect(v, v.requestWire, now));
    }
    for (const changes of [{ expiresAt: c.issuedAt }, { expiresAt: c.issuedAt + 60001 },
      { issuedAt: -1 }, { issuedAt: true }, { expiresAt: 1.5 }, { expiresAt: Number.MAX_SAFE_INTEGER + 1 },
      { challengeId: "aa" }, { domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V1" }]) {
      denied(() => inspectDeviceChallengeCandidateV1(change(v.challengeWire, changes), v.requestWire, c.issuedAt, on));
    }
  });
}

test("altered valid ciphertext, nonce, message identity and recipient wraps cannot reuse a challenge", () => {
  const v = vectors[0];
  for (const mutate of [
    (e) => { e.body.ciphertext = Buffer.alloc(97, 1).toString("base64url"); },
    (e) => { e.body.nonce = Buffer.alloc(12, 2).toString("base64url"); },
    (e) => { e.messageId = "m_" + Buffer.alloc(32, 3).toString("base64url"); },
    (e) => { e.keyWraps[0].ciphertext = Buffer.alloc(48, 4).toString("base64url"); }
  ]) {
    const envelope = JSON.parse(v.bodyWire);
    mutate(envelope);
    denied(() => inspect(v, build(v, v.contextWire, JSON.stringify(envelope))));
  }
  for (const body of [" " + v.bodyWire, v.bodyWire + "\n", change(v.bodyWire, { subject: "aa".repeat(32) }),
    v.bodyWire.replace('"version":1', '"version":1,"version":1'), "x".repeat(32769)]) {
    denied(() => build(v, v.contextWire, body));
  }
});

test("recipient-self binds one canonical handle; no subject, list, discovery or cursor selectors", () => {
  const v = vectors[1];
  const other = "d_" + Buffer.alloc(16, 8).toString("base64url");
  denied(() => inspect(v, build(v, v.contextWire, change(v.bodyWire, { deviceHandle: other }))));
  for (const changes of [{ subject: "aa".repeat(32) }, { deviceId: "22".repeat(32) },
    { handles: [other] }, { cursor: "future-cursor" }, { deviceHandle: "*" }, { deviceHandle: null },
    { deviceHandle: other.slice(0, -1) + "h" }, { version: true }]) {
    denied(() => build(v, v.contextWire, change(v.bodyWire, changes)));
  }
  denied(() => inspect(v, vectors[0].requestWire));
  denied(() => inspect(vectors[0], v.requestWire));
});

test("closed canonical parsers reject alternate representations and unbounded data", () => {
  const v = vectors[0];
  for (const wire of [v.requestWire + "\n", " " + v.requestWire, JSON.parse(v.requestWire), Buffer.from(v.requestWire),
    v.requestWire.replace('"version":1', '"version":1,"version":1'),
    v.requestWire.replace('"version":1', '"version":1.0'),
    v.requestWire.replace('"version":1', '"version":1e0'),
    v.requestWire.replace("POST", "P\\u004fST"), change(v.requestWire, { publicKey: "ee".repeat(32) }),
    change(v.requestWire, { version: true }), change(v.requestWire, { subject: "é" }),
    change(v.requestWire, { bindingVersion: 1025 }), "x".repeat(2049), "null", "[]", "{}"] ) {
    denied(() => parseDeviceRequestCandidateV1(wire, on));
  }
  for (const wire of [v.contextWire + "\n", change(v.contextWire, { cookie: "forbidden" }),
    change(v.contextWire, { audience: "https://social.example/" }), "x".repeat(1025)]) {
    denied(() => build(v, wire));
  }
  for (const wire of [v.challengeWire + "\n", v.challengeWire.replace('"version":1}', '"version":1,"version":1}'),
    change(v.challengeWire, { proof: "not-a-proof" }), "x".repeat(4097)]) {
    denied(() => digestDeviceChallengeCandidateV1(wire, on));
  }
});

test("candidate construction cannot invoke caller coercion or serialization hooks", () => {
  const evil = { toJSON() { assert.fail("toJSON ran"); }, toString() { assert.fail("toString ran"); } };
  const v = vectors[0], c = JSON.parse(v.challengeWire);
  denied(() => build(v, v.contextWire, v.bodyWire, evil));
  denied(() => build(v, v.contextWire, v.bodyWire, "POST", evil));
  denied(() => createDeviceChallengeCandidateV1(v.requestWire, evil, c.issuedAt, c.expiresAt, on));
  denied(() => createDeviceChallengeCandidateV1(v.requestWire, c.challengeId, evil, c.expiresAt, on));
});

test("admission remains impossible for every proof/authority claim, including explicit enablement and replay", () => {
  assert.equal(DEVICE_ADMISSION_ENABLED, false);
  assert.equal(APPROVED_DEVICE_PROOF_PROFILE, null);
  const verifier = { verifyInTransaction() { assert.fail("unapproved verifier invoked"); } };
  for (const v of vectors) {
    for (const evidence of [undefined, { session: "current-full-session" }, { qrScan: true },
      { acceptedBinding: true }, { proof: "historical-nostr-approval" }, { proof: "historical-mobile-acceptance" },
      { bindingState: "revoked" }, { bindingState: "rotated" }, { bindingState: "expired" },
      { bindingState: "missing" }, { bindingState: "ambiguous" }, { currentFull: false },
      { currentFull: true, currentBinding: true, proof: "unapproved-signature" }]) {
      const attempt = { challenge: v.challengeWire, request: v.requestWire, evidence, verifier };
      denied(() => admitMessagingDeviceRequestV1(attempt));
      denied(() => admitMessagingDeviceRequestV1(attempt, on));
      denied(() => admitMessagingDeviceRequestV1(attempt, on));
    }
  }
  denied(() => admitMessagingDeviceRequestV1(new Proxy({}, { get() { assert.fail("attempt inspected"); } }), on));
});

test("contract module remains outside runtime and authenticated browser composition", async () => {
  for (const path of ["../scripts/hodlxxi-social-server.mjs", "../src/server/social-oauth-bff.mjs",
    "../src/server/social-mobile-runtime-v1.mjs", "../src/server/social-mobile-composition-v1.mjs", "../web/auth-entry.mjs"]) {
    assert.doesNotMatch(await readFile(new URL(path, import.meta.url), "utf8"), /messaging-device-admission-v1/);
  }
});
