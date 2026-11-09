import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createUbidSocialEnrollmentV2Client as createClient, ENROLLMENT_PREFIX as PREFIX,
  ENROLLMENT_TOKEN_PATH as TOKEN_PATH, ENROLLMENT_SCOPES as SCOPES,
  FinalizeOutcomeUnknown, SOCIAL_ENROLLMENT_V2_CLIENT_ENABLED } from "../src/server/ubid-social-enrollment-v2-client.mjs";
import { canonical } from "../web/social-mobile-protocol-v1.mjs";

const vector = JSON.parse(readFileSync(new URL("./fixtures/social_preacceptance_ed25519_handoff_v2.json", import.meta.url))).vector;
const enrollment = JSON.parse(vector.enrollmentWire), context = JSON.parse(vector.verificationContextWire);
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const denied = { message: "social enrollment v2 unavailable" };
const reservationId = "a".repeat(64), issuanceId = "c".repeat(64), effectId = "e".repeat(64);
const inputWire = vector.preacceptedEnrollmentVerificationInputWire;
const digest = (domain, wire) => createHash("sha256").update(domain + "\0" + wire, "ascii").digest("hex");
const tagged = (label, domain, wire) => `${label}-sha256:${digest(domain, wire)}`;
const inputDigest = tagged("hodlxxi-social-preaccepted-enrollment-verification-input-v2",
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2", inputWire);
const inputPayloadDigest = tagged("hodlxxi-social-messaging-device-verification-deadline-input-payload-v1",
  "HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_INPUT_PAYLOAD_V1", inputWire);
const evidenceCompactJws = `header.${Buffer.from(canonical({ inputDigest, inputPayloadDigest,
  socialSessionIssuanceId: issuanceId, reservationId, reservationRevision: 1 })).toString("base64url")}.signature`;
const statementCompactJws = "other.payload.signature";
const evidenceDigest = tagged("hodlxxi-social-preaccepted-enrollment-v2-deadline-evidence-v1",
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_DEADLINE_EVIDENCE_V1", evidenceCompactJws);
const statementDigest = tagged("hodlxxi-social-preaccepted-enrollment-v2-verification-statement-v1",
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_VERIFICATION_STATEMENT_V1", statementCompactJws);
const finalizationRequestDigest = tagged("hodlxxi-social-preaccepted-enrollment-v2-finalization-request-v1",
  "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_FINALIZATION_REQUEST_V1", canonical({ evidenceDigest,
    inputDigest, inputPayloadDigest, reservationId, reservationRevision: 1, statementDigest }));
const effectDigest = "hodlxxi-social-preaccepted-enrollment-v2-effect-v1-sha256:" + "d".repeat(64);
const receiptId = digest("HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_RECEIPT_ID_V1", canonical({
  effectDigest, effectId, finalizationRequestDigest, reservationId, reservationRevision: 1,
  schema: "hodlxxi.social_preaccepted_enrollment_v2_receipt_id_preimage.v1", version: 1,
}));
const common = (name) => ({ schema: `hodlxxi.social_enrollment_v2_${name}_publication.v1`, version: 1,
  publicationStatus: "committed", finalAdmission: "denied", bearerAuthority: "none" });
const responseFor = (name) => name === "challenge" ? { ...common(name), contextWire: vector.verificationContextWire,
  enrollmentWire: vector.enrollmentWire, approvalEventWire: vector.approvalEventWire, challengeRevision: 1,
  issuedAt: enrollment.issuedAt, expiresAt: enrollment.expiresAt } : name === "reserve"
  ? { ...common(name), evidenceCompactJws: "header.payload.signature", reservationId: "a".repeat(64),
      observedAt: enrollment.issuedAt, expiresAt: enrollment.expiresAt }
  : { ...common(name), historicalRecovery: true, receiptWire: canonical({
      schema: "hodlxxi.social_preaccepted_enrollment_v2_acceptance_receipt.v1", version: 1, status: "committed",
      reservationId, reservationRevision: 1, receiptId, effectId, effectDigest, evidenceDigest, inputDigest,
      statementDigest, finalizationRequestDigest, acceptanceId: JSON.parse(inputWire).acceptanceId,
      challengeId: context.challengeId, associationId: context.associationId, decidedAt: enrollment.issuedAt }) };
function body(name) {
  const value = { issuanceId };
  if (name !== "challenge") value.verificationInputWire = inputWire;
  if (name === "finalize") Object.assign(value, { reservationId, reservationRevision: "1",
    evidenceCompactJws, statementCompactJws });
  return value;
}
function setup(patch = {}) {
  const calls = [], assertions = new Set();
  const state = { now: enrollment.issuedAt, mode: "valid", change: undefined, ...patch };
  const config = { enabled: true, issuerOrigin: "https://ubid.example", socketPath: "/tmp/synthetic-enrollment.sock",
    clientId: "social-backend", clientSigningKeyId: "test-client", signingKey: privateKey, timeoutMs: 250 };
  function requestImpl(options, received) {
    calls.push(options);
    const req = new EventEmitter(); req.destroy = () => { req.destroyed = true; };
    req.end = (raw) => queueMicrotask(() => {
      if (state.mode === "hang") return;
      const token = options.path === TOKEN_PATH;
      let value;
      if (token) {
        const form = new URLSearchParams(raw), assertion = form.get("client_assertion");
        const [h, p, sig] = assertion.split(".");
        assert.equal(verify("RSA-SHA256", Buffer.from(h + "." + p), publicKey, Buffer.from(sig, "base64url")), true);
        const claims = JSON.parse(Buffer.from(p, "base64url"));
        assert.equal(claims.aud, config.issuerOrigin + TOKEN_PATH);
        assert.equal(claims.purpose, "service_client_authentication");
        assert.equal(claims.exp - claims.iat, 60);
        assert.equal(assertions.has(claims.jti), false); assertions.add(claims.jti);
        assert.equal(options.headers.Authorization, undefined);
        assert.equal(options.headers["X-HODLXXI-Viewer-Authorization"], undefined);
        value = { access_token: "service.exact.credential", token_type: "Bearer", expires_in: 60, scope: form.get("scope") };
        state.scope = form.get("scope");
      } else {
        const name = options.path.slice(PREFIX.length + 1);
        assert.equal(state.scope, SCOPES[name]);
        assert.equal(options.headers.Authorization, "Bearer service.exact.credential");
        assert.equal(options.headers["X-HODLXXI-Viewer-Authorization"], "Bearer phone.exact.credential");
        assert.deepEqual(JSON.parse(raw), body(name));
        value = responseFor(name);
      }
      if (state.change) value = state.change(value, token);
      let wire = typeof value === "string" ? value : canonical(value);
      const res = new EventEmitter(); res.statusCode = state.mode === "redirect" ? 302 : 200;
      res.destroy = () => { res.destroyed = true; }; res.complete = state.mode !== "incomplete";
      res.rawHeaders = ["Content-Type", "application/json", "Content-Length", String(Buffer.byteLength(wire)),
        "Cache-Control", "no-store", "Pragma", "no-cache"];
      if (state.mode === "duplicate-header") res.rawHeaders.push("content-type", "application/json");
      if (state.mode === "encoding") res.rawHeaders.push("Content-Encoding", "gzip");
      if (state.mode === "length") res.rawHeaders[3] = String(Buffer.byteLength(wire) + 1);
      if (state.mode === "no-cache-policy") res.rawHeaders[5] = "public";
      received(res);
      if (state.mode === "oversize") wire += " ";
      res.emit("data", Buffer.from(wire)); res.emit("end");
    });
    return req;
  }
  const dependencies = { requestImpl, now: () => state.now, random: (n) => {
    // Deterministic test nonce sequence, distinct across assertion calls.
    const value = Buffer.alloc(n); value.writeUInt32BE(assertions.size + 1); return value;
  } };
  return { client: createClient(config, dependencies), config, dependencies, state, calls, assertions };
}
const args = (name) => ({ body: body(name), viewerAccessToken: "phone.exact.credential" });

test("disabled client performs no key/configuration or transport access", () => {
  assert.equal(SOCIAL_ENROLLMENT_V2_CLIENT_ENABLED, false);
  assert.equal(createClient(), undefined);
  assert.equal(createClient({ enabled: false, get signingKey() { throw Error("must not read"); } }), undefined);
});
test("literal enable and closed trusted construction reject getters/proxies/extras", () => {
  const s = setup();
  for (const value of [1, "true", null]) assert.throws(() => createClient({ enabled: value }), denied);
  for (const config of [{ ...s.config, extra: true }, new Proxy(s.config, {}),
    { ...s.config, get clientId() { throw Error("private marker"); } }]) assert.throws(() => createClient(config, s.dependencies), denied);
});
test("no TCP URL, noncanonical socket, weak key or unbounded timeout fallback", () => {
  const s = setup();
  for (const change of [{ issuerOrigin: "http://ubid.example" }, { issuerOrigin: "https://UBID.example" },
    { socketPath: "/tmp/../live.sock" }, { socketPath: "relative.sock" }, { signingKey: publicKey },
    { timeoutMs: 0 }, { timeoutMs: 30001 }, { timeoutMs: true }]) assert.throws(() => createClient({ ...s.config, ...change }, s.dependencies), denied);
});
test("all three methods use real RS256 assertions, exact scopes/headers/wires and fixed Unix paths", async () => {
  const s = setup();
  for (const name of ["challenge", "reserve", "finalize"]) {
    const result = await s.client[name](args(name));
    assert.deepEqual(result, responseFor(name)); assert.equal(Object.isFrozen(result), true);
    assert.equal(result.finalAdmission, "denied"); assert.equal(result.bearerAuthority, "none");
  }
  assert.equal(s.calls.length, 6); assert.equal(s.assertions.size, 3);
  for (const call of s.calls) {
    assert.equal(call.socketPath, s.config.socketPath); assert.equal(call.method, "POST");
    assert.equal(call.hostname, undefined); assert.equal(call.port, undefined); assert.equal(call.agent, false);
  }
});
test("invalid viewer and request-selected clock/identity/profile deny before service-token call", async () => {
  const s = setup();
  for (const input of [{ ...args("challenge"), viewerAccessToken: "bad" }, { ...args("challenge"), now: 1 },
    { ...args("challenge"), body: { ...body("challenge"), subject: "chosen" } },
    { ...args("challenge"), body: new Proxy(body("challenge"), {}) }]) await assert.rejects(s.client.challenge(input), denied);
  assert.equal(s.calls.length, 0);
});
test("duplicate, alternate escaped and oversized input wire deny before I/O", async () => {
  const s = setup();
  for (const wire of ['{"x":1,"x":2}', '{"x":"\\u0061"}', " ".repeat(24577)])
    await assert.rejects(s.client.reserve({ ...args("reserve"), body: { ...body("reserve"), verificationInputWire: wire } }), denied);
  assert.equal(s.calls.length, 0);
});
for (const mode of ["redirect", "duplicate-header", "encoding", "length", "no-cache-policy", "oversize", "incomplete"]) {
  test(`malformed ${mode} response denies without retry or command dispatch`, async () => {
    const s = setup({ mode }); await assert.rejects(s.client.challenge(args("challenge")), denied);
    assert.equal(s.calls.length, 1);
  });
}
test("timeout aborts exact request and never starts fallback or retry", async () => {
  const s = setup({ mode: "hang" }); await assert.rejects(s.client.challenge(args("challenge")), denied);
  assert.equal(s.calls.length, 1);
});
test("wrong service scope or same viewer/service token denies before command", async () => {
  for (const change of [(v) => ({ ...v, scope: SCOPES.finalize }), (v) => ({ ...v, access_token: "phone.exact.credential" })]) {
    const s = setup({ change }); await assert.rejects(s.client.challenge(args("challenge")), denied);
    assert.equal(s.calls.length, 1);
  }
});
test("uncommitted, admitted, bearer-grant, unknown-field and wrong-schema publications deny", async () => {
  for (const change of [{ publicationStatus: "provisional_until_caller_commit" }, { finalAdmission: "allowed" },
    { bearerAuthority: "access" }, { extra: true }, { schema: "other" }]) {
    const s = setup({ change: (v, token) => token ? v : { ...v, ...change } });
    await assert.rejects(s.client.challenge(args("challenge")), denied); assert.equal(s.calls.length, 2);
  }
});
test("expired or mismatched challenge response is never refreshed", async () => {
  for (const change of [{ expiresAt: enrollment.issuedAt }, { challengeRevision: 2 },
    { enrollmentWire: canonical({ ...enrollment, subject: "f".repeat(64) }) }]) {
    const s = setup({ change: (v, token) => token ? v : { ...v, ...change } });
    await assert.rejects(s.client.challenge(args("challenge")), denied); assert.equal(s.calls.length, 2);
  }
});
test("response clocks cannot move backwards or extend an expired interval", async () => {
  const s = setup({ change: (v, token) => { if (token) s.state.now--; return v; } });
  await assert.rejects(s.client.challenge(args("challenge")), denied); assert.equal(s.calls.length, 1);
});
test("invalid finalize publications leave the already dispatched outcome unknown", async () => {
  const receipt = JSON.parse(responseFor("finalize").receiptWire);
  for (const change of [{ historicalRecovery: 1 },
    { receiptWire: canonical({ ...receipt, reservationId: "f".repeat(64) }) },
    { receiptWire: canonical({ ...receipt, receiptId: "f".repeat(64) }) }]) {
    const s = setup({ change: (v, token) => token ? v : { ...v, ...change } });
    await assert.rejects(s.client.finalize(args("finalize")), FinalizeOutcomeUnknown);
    assert.equal(s.calls.length, 2);
  }
});
test("transport failure text is sanitized and contains no provider error", async () => {
  const s = setup(); const client = createClient(s.config, { ...s.dependencies, requestImpl() { throw Error("private-marker"); } });
  await assert.rejects(client.challenge(args("challenge")), denied);
});
