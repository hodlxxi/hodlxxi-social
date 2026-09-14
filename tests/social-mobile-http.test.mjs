import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { generateKeyPairSync, verify } from "node:crypto";
import { createUbidMobileAuthorizationClient, createUbidSessionIssuanceClient } from "../src/server/ubid-social-mobile-client-v1.mjs";
import { createSocialMobileComposition } from "../src/server/social-mobile-composition-v1.mjs";
import { createHttpHandler } from "../scripts/hodlxxi-social-server.mjs";
import { createSessionStore, createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { canonical, MOBILE_COMMANDS, MOBILE_PREFIX, ISSUANCE_PREFIX } from "../web/social-mobile-protocol-v1.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const token = "synthetic.service.credential", viewer = "synthetic.viewer.credential";
const issuerOrigin = "https://identity.example";
const config = { publicOrigin: "https://social.example", authorityOrigin: issuerOrigin, clientId: "social", callbackUri: "https://social.example/auth/callback", scope: "openid", transactionTtlSeconds: 300, sessionTtlSeconds: 3600 };
async function listening(t, handler) {
  const root = await mkdtemp(tmpdir() + "/social-2b-http-"), socketPath = root + "/http.sock";
  const server = http.createServer(handler); server.listen(socketPath); await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise((r) => server.close(r)); await rm(root, { recursive: true }); });
  return socketPath;
}
function request(socketPath, path, body = "{}", headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path, method: "POST", agent: false, headers: { Host: "social.example", "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), Origin: config.publicOrigin, ...headers } }, (res) => {
      const chunks = []; res.on("data", (v) => chunks.push(v)); res.once("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() })); res.once("error", reject);
    }); req.once("error", reject); req.setTimeout(3000, () => req.destroy(Error("test deadline"))); req.end(body);
  });
}
test("actual Unix HTTP confidential assertions, exact scopes/headers and canonical fixed paths", async (t) => {
  const assertions = new Set(), requests = []; let mode = "valid";
  const socketPath = await listening(t, async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString(); requests.push(req.url);
    let result;
    if (req.url.endsWith("/service-token")) {
      const form = new URLSearchParams(body), assertion = form.get("client_assertion"), [h, p, sig] = assertion.split(".");
      assert.equal(verify("RSA-SHA256", Buffer.from(h + "." + p), publicKey, Buffer.from(sig, "base64url")), true);
      const claims = JSON.parse(Buffer.from(p, "base64url"));
      assert.equal(claims.aud, issuerOrigin + req.url); assert.equal(claims.iss, "test-client"); assert.equal(claims.sub, "test-client");
      assert.equal(assertions.has(claims.jti), false); assertions.add(claims.jti);
      assert.equal(req.headers["x-hodlxxi-viewer-authorization"], undefined);
      result = { access_token: token, token_type: "Bearer", expires_in: 60, scope: form.get("scope") };
      if (mode === "wrong-scope") result.scope = "social:full-directory:read";
    } else {
      assert.equal(req.headers.authorization, "Bearer " + token);
      assert.equal(req.headers["x-hodlxxi-viewer-authorization"], req.url.endsWith("/resolve") || req.url.endsWith("/revoke") || req.url.endsWith("/legacy/status") ? "Bearer " + viewer : undefined);
      assert.equal(canonical(JSON.parse(body)), body);
      if (req.url.endsWith("/legacy/status")) result = { status: "expired", authorizationDigest: "a".repeat(64) };
      else result = { schema: "hodlxxi.social_session_revocation.v1", version: 1, issuanceId: "b".repeat(64), status: "revoked" };
    }
    let source = canonical(result);
    if (mode === "duplicate") source = source.replace("{", '{"scope":"duplicate",');
    if (mode === "oversized") source = "x".repeat(70000);
    if (mode === "deep") source = '{"a":[[[[[[[0]]]]]]]}';
    res.writeHead(mode === "redirect" ? 302 : 200, { "Content-Type": mode === "content-type" ? "text/html" : "application/json", "Content-Length": Buffer.byteLength(source), "Cache-Control": "no-store", Pragma: "no-cache", ...(mode === "encoding" ? { "Content-Encoding": "gzip" } : {}) }); res.end(source);
  });
  const c = { enabled: true, issuerOrigin, socketPath, clientId: "test-client", clientSigningKeyId: "client-test", signingKey: privateKey, timeoutMs: 1000 };
  const mobile = createUbidMobileAuthorizationClient(c), issuance = createUbidSessionIssuanceClient(c);
  const input = { body: { operationId: "12345678-1234-4234-8234-123456789abc" }, viewerAccessToken: viewer };
  assert.equal((await mobile.legacyStatus(input)).status, "expired");
  assert.equal((await issuance.revoke({ body: { issuanceId: "b".repeat(64) }, viewerAccessToken: viewer })).status, "revoked");
  assert.deepEqual(requests, [MOBILE_PREFIX + "/service-token", MOBILE_PREFIX + "/legacy/status", ISSUANCE_PREFIX + "/service-token", ISSUANCE_PREFIX + "/revoke"]);
  for (mode of ["wrong-scope", "duplicate", "oversized", "deep", "redirect", "content-type", "encoding"]) await assert.rejects(mobile.legacyStatus(input));
  const before = requests.length;
  for (const bad of [{ body: input.body }, { ...input, subject: "a".repeat(64) }, { ...input, body: { ...input.body, viewerAccessToken: viewer } }]) await assert.rejects(mobile.legacyStatus(bad));
  await assert.rejects(mobile.phoneStatus({ body: {}, viewerAccessToken: viewer }));
  assert.equal(requests.length, before);
});

test("actual Social HTTP dispatch is dormant by default and strictly framed when injected", async (t) => {
  let calls = 0;
  const mobileClient = Object.fromEntries(Object.keys(MOBILE_COMMANDS).map((name) => [name, async () => { calls++; throw Error("no authority"); }]));
  const issuanceClient = Object.fromEntries(["issue", "recover", "resolve", "revoke"].map((name) => [name, async () => { calls++; throw Error("no authority"); }]));
  const dependencies = { config, sessions: createSessionStore({ ttlSeconds: 3600, capacity: 10 }), pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10 }), oauthClient: {} };
  const off = createSocialMobileComposition({ ...dependencies, mobileClient, issuanceClient });
  const offSocket = await listening(t, createHttpHandler({ publicOrigin: config.publicOrigin, bff: off.bff, mobilePostRoutes: off.mobilePostRoutes }));
  assert.equal((await request(offSocket, "/auth/mobile/v1/context")).status, 413); assert.equal(calls, 0);
  const on = createSocialMobileComposition({ ...dependencies, enabled: true, mobileClient, issuanceClient });
  const socketPath = await listening(t, createHttpHandler({ publicOrigin: config.publicOrigin, bff: on.bff, mobilePostRoutes: on.mobilePostRoutes }));
  const context = await request(socketPath, "/auth/mobile/v1/context"); assert.equal(context.status, 200);
  const restarted = await request(socketPath, "/auth/mobile/v1/context", "{}", { Cookie: "__Host-hodlxxi-social-session=old-unknown-cookie" });
  assert.equal(restarted.status, 200); assert.match(restarted.headers["set-cookie"][0], /Max-Age=0/); assert.equal(dependencies.sessions.size, 0);
  const csrf = JSON.parse(context.body).csrf, cookie = context.headers["set-cookie"][0].split(";")[0];
  for (const [path, body, headers] of [
    ["/auth/mobile/v1/context?subject=x", "{}", {}],
    ["/auth/mobile/v1/context", '{"a":1,"a":2}', {}],
    ["/auth/mobile/v1/context", "{}", { Origin: "https://evil.example" }],
    ["/auth/mobile/v1/context", "{}", { "Content-Encoding": "gzip" }],
    ["/auth/mobile/v1/context", "{}", { Authorization: "Bearer browser" }],
    ["/auth/mobile/v1/qr/create", "{}", { Cookie: cookie }],
    ["/auth/mobile/v1/qr/create", "{}", { Cookie: cookie, "x-hodlxxi-mobile-csrf": csrf }],
    ["/auth/mobile/v1/session/issue", '{"viewerAccessToken":"forged.jwt.value"}', { Cookie: cookie, "x-hodlxxi-mobile-csrf": csrf }]
  ]) assert.notEqual((await request(socketPath, path, body, headers)).status, 200);
  assert.equal(calls, 0);
  // Raw socket cardinality checks cannot be tested using normalized headers.
  for (const extra of ["Origin: https://social.example\r\n", "Cookie: duplicate=value\r\n", "Content-Type: application/json\r\n", "Content-Length: 2\r\n", "Transfer-Encoding: chunked\r\n"]) {
    const socket = net.createConnection(socketPath); await once(socket, "connect"); let response = "";
    socket.setEncoding("utf8"); socket.on("data", (s) => { response += s; });
    socket.write("POST /auth/mobile/v1/context HTTP/1.1\r\nHost: social.example\r\nOrigin: https://social.example\r\nCookie: test=one\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n" + extra + "\r\n{}");
    await once(socket, "close"); assert.match(response, /^HTTP\/1\.1 (400|413)/);
  }
});
