import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";
import { canonical } from "../web/social-mobile-protocol-v1.mjs";
import { createUbidSocialSessionV2Client as createClient, SESSION_PREFIX as PREFIX,
  SESSION_TOKEN_PATH as TOKEN_PATH, SESSION_SCOPES as SCOPES,
  validateNativeV2SessionResponse, SOCIAL_NATIVE_V2_SESSION_ENABLED } from "../src/server/ubid-social-session-v2-client.mjs";

const at = 1700000000000, hex = (c) => c.repeat(64);
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const denied = { message: "native v2 session unavailable" };
const receipt = () => ({ schema: "hodlxxi.social_session_issuance.v2", version: 2, issuanceId: hex("a"),
  socialSessionIssuanceRevision: hex("b"), acceptanceId: hex("c"), issuedAt: at, expiresAt: at + 60000 });
function body(name) {
  if (name === "offer") return { authorizationWire: canonical({ original: "v2-envelope" }) };
  if (["resolve", "revoke"].includes(name)) return { issuanceId: hex("a") };
  return { operationId: hex("d"), approvalWire: canonical({ original: "v2-approval" }),
    secret: hex("e"), possessionProof: hex("f"), verifier: hex("1"), deliveryKey: hex("2") };
}
function responseFor(name) {
  if (name === "offer") return body(name);
  if (name === "revoke") return { schema: "hodlxxi.social_session_revocation.v2", version: 2, issuanceId: hex("a"), status: "revoked" };
  return { receipt: receipt(), subject: hex("3"), currentActive: true,
    ...(name === "resolve" ? {} : { viewerAccessToken: "native.exact.child" }) };
}
const args = (name) => ({ body: body(name), ...(name === "recover" ? {} : { viewerAccessToken: "original.exact.viewer" }) });
function setup(changes = {}) {
  const state = { now: at, mode: "valid", ...changes }, calls = [], nonces = new Set();
  const config = { enabled: true, issuerOrigin: "https://ubid.example", socketPath: "/tmp/synthetic-v2-session.sock",
    clientId: "backend", clientSigningKeyId: "test-client", signingKey: privateKey, timeoutMs: 250 };
  const requestImpl = (options, receive) => {
    calls.push(options);
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = (raw) => queueMicrotask(() => {
      const token = options.path === TOKEN_PATH;
      let value;
      if (token) {
        const form = new URLSearchParams(raw), assertion = form.get("client_assertion");
        const [header, payload, signature] = assertion.split(".");
        assert.equal(verify("RSA-SHA256", Buffer.from(header + "." + payload), publicKey, Buffer.from(signature, "base64url")), true);
        const claims = JSON.parse(Buffer.from(payload, "base64url"));
        assert.equal(claims.aud, config.issuerOrigin + TOKEN_PATH);
        assert.equal(claims.exp - claims.iat, 60); assert.equal(claims.purpose, "service_client_authentication");
        assert.equal(nonces.has(claims.jti), false); nonces.add(claims.jti);
        assert.equal(options.headers.Authorization, undefined);
        assert.equal(options.headers["X-HODLXXI-Viewer-Authorization"], undefined);
        state.scope = form.get("scope");
        value = { access_token: "service.exact.token", token_type: "Bearer", expires_in: 60, scope: state.scope };
      } else {
        const name = options.path.slice(PREFIX.length + 1);
        assert.equal(state.scope, SCOPES[name]);
        assert.equal(options.headers.Authorization, "Bearer service.exact.token");
        assert.equal(options.headers["X-HODLXXI-Viewer-Authorization"], name === "recover" ? undefined : "Bearer original.exact.viewer");
        assert.deepEqual(JSON.parse(raw), body(name)); value = responseFor(name);
      }
      if (state.change) value = state.change(value, token);
      const wire = typeof value === "string" ? value : canonical(value), res = new EventEmitter();
      res.statusCode = state.mode === "redirect" ? 302 : 200; res.complete = true; res.destroy = () => {};
      res.rawHeaders = ["Content-Type", "application/json", "Content-Length", String(Buffer.byteLength(wire)),
        "Cache-Control", "no-store", "Pragma", "no-cache"];
      if (state.mode === "duplicate") res.rawHeaders.push("content-type", "application/json");
      if (state.mode === "encoding") res.rawHeaders.push("Content-Encoding", "gzip");
      receive(res); res.emit("data", Buffer.from(wire)); res.emit("end");
    });
    return req;
  };
  const deps = { requestImpl, now: () => state.now, random: (n) => { const b = Buffer.alloc(n); b.writeUInt32BE(nonces.size + 1); return b; } };
  return { client: createClient(config, deps), config, deps, state, calls, nonces };
}
test("disabled construction never reads keys or opens transport", () => {
  assert.equal(SOCIAL_NATIVE_V2_SESSION_ENABLED, false); assert.equal(createClient(), undefined);
  assert.equal(createClient({ enabled: false, get signingKey() { throw Error("must-not-read"); } }), undefined);
});
test("all five commands use real assertion signatures and independent exact scopes", async () => {
  const s = setup();
  for (const name of Object.keys(SCOPES)) assert.deepEqual(await s.client[name](args(name)), responseFor(name));
  assert.equal(s.calls.length, 10); assert.equal(s.nonces.size, 5);
  for (const call of s.calls) {
    assert.equal(call.socketPath, s.config.socketPath); assert.equal(call.method, "POST");
    assert.equal(call.hostname, undefined); assert.equal(call.port, undefined); assert.equal(call.agent, false);
  }
});
test("recover rejects any viewer field before network and never falls back to V1", async () => {
  const s = setup();
  await assert.rejects(s.client.recover({ ...args("recover"), viewerAccessToken: "extra.exact.viewer" }), denied);
  assert.equal(s.calls.length, 0);
});
test("request-selected identity, profile, time, getters and malformed proofs deny before I/O", async () => {
  const s = setup(); let invoked = false;
  for (const change of [{ now: 1 }, { body: { ...body("issue"), subject: hex("3") } },
    { body: { ...body("issue"), secret: "bad" } }, { body: { ...body("issue"), get verifier() { invoked = true; return hex("1"); } } }])
    await assert.rejects(s.client.issue({ ...args("issue"), ...change }), denied);
  assert.equal(invoked, false); assert.equal(s.calls.length, 0);
});
for (const mode of ["redirect", "duplicate", "encoding"]) test(`ambiguous ${mode} response never dispatches or retries`, async () => {
  const s = setup({ mode }); await assert.rejects(s.client.issue(args("issue")), denied); assert.equal(s.calls.length, 1);
});
test("V1 receipt, integer revision and extra receipt fields cannot become V2 authority", async () => {
  for (const change of [{ schema: "hodlxxi.social_session_issuance.v1" }, { socialSessionIssuanceRevision: 1 }, { extra: true }]) {
    const s = setup({ change: (v, token) => token ? v : { ...v, receipt: { ...v.receipt, ...change } } });
    await assert.rejects(s.client.issue(args("issue")), denied);
  }
});
test("offer retry must retain exact original bytes", async () => {
  const s = setup({ change: (v, token) => token ? v : { authorizationWire: canonical({ original: "replacement" }) } });
  await assert.rejects(s.client.offer(args("offer")), denied);
});
test("service and desktop credentials cannot be installed as the native child", async () => {
  for (const bearer of ["service.exact.token", "original.exact.viewer"]) {
    const s = setup({ change: (v, token) => token ? v : { ...v, viewerAccessToken: bearer } });
    await assert.rejects(s.client.issue(args("issue")), denied);
  }
});
test("late service response denies delivery without retry", async () => {
  const s = setup({ change: (v, token) => { if (!token) s.state.now += 60000; return v; } });
  await assert.rejects(s.client.issue(args("issue")), denied); assert.equal(s.calls.length, 2);
});
test("inactive exact history has no bearer or subject; expiry is exclusive", () => {
  const inactive = { ...responseFor("issue"), currentActive: false, viewerAccessToken: null, subject: null };
  assert.equal(validateNativeV2SessionResponse(inactive, at + 900000).currentActive, false);
  assert.throws(() => validateNativeV2SessionResponse(responseFor("issue"), at + 60000), denied);
  assert.throws(() => validateNativeV2SessionResponse({ ...inactive, viewerAccessToken: "bad.exact.credential" }, at), denied);
});
test("trusted construction rejects TCP, path traversal, public key and unknown configuration", () => {
  const s = setup();
  for (const change of [{ issuerOrigin: "http://ubid.example" }, { socketPath: "/tmp/../live.sock" },
    { signingKey: publicKey }, { timeoutMs: true }, { extra: true }])
    assert.throws(() => createClient({ ...s.config, ...change }, s.deps), denied);
});
