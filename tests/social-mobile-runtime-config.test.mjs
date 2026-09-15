import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { configFromEnvironment } from "../src/server/social-oauth-config.mjs";
import { createSessionServiceIntegration, createSocialMobileRuntime } from "../src/server/social-mobile-runtime-v1.mjs";
import { createUbidSessionIssuanceClient } from "../src/server/ubid-social-mobile-client-v1.mjs";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs";
import { createBoundedStore, createSessionStore } from "../src/server/social-oauth-memory.mjs";
import { createHttpHandler, createRecipientCapabilityIntegration, runServer } from "../scripts/hodlxxi-social-server.mjs";

const env = {
  SOCIAL_PUBLIC_ORIGIN: "https://social.example", HODLXXI_AUTHORITY_ORIGIN: "https://identity.example",
  HODLXXI_OAUTH_CLIENT_ID: "client_HcWQhI45Cm92N_tRWHGRb-O3pdZKDDAdVnk4_1TVrtY",
  HODLXXI_OAUTH_CLIENT_SECRET: "synthetic-secret", SOCIAL_BIND_HOST: "127.0.0.1", SOCIAL_PORT: "8080",
  SOCIAL_TRANSACTION_TTL_SECONDS: "300", SOCIAL_SESSION_TTL_SECONDS: "3600", SOCIAL_MAX_PENDING_TRANSACTIONS: "10",
  SOCIAL_MAX_SESSIONS: "10", SOCIAL_OUTBOUND_TIMEOUT_MS: "1000"
};
const issuanceEnv = {
  SOCIAL_UBID_SESSION_ISSUANCE_ENABLED: "true",
  SOCIAL_UBID_SESSION_ISSUANCE_ISSUER_ORIGIN: "https://identity.example",
  SOCIAL_UBID_SESSION_ISSUANCE_PRIVATE_SOCKET_PATH: "/tmp/synthetic-issuance.sock",
  SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID: "social-staging-session-issuance-service-v1",
  SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_SIGNING_KEY_ID: "synthetic-service-key",
  SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_SIGNING_KEY_PATH: "/tmp/never-read-operational-key.pem",
  SOCIAL_UBID_SESSION_ISSUANCE_TIMEOUT_MS: "1000"
};
const mobileEnv = {
  SOCIAL_MOBILE_ENABLED: "true",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_ISSUER_ORIGIN: "https://identity.example",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_PRIVATE_SOCKET_PATH: "/tmp/synthetic-mobile.sock",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_ID: "synthetic-mobile-backend",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_SIGNING_KEY_ID: "synthetic-mobile-key",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_SIGNING_KEY_PATH: "/tmp/never-read-mobile-key.pem",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_TIMEOUT_MS: "1000"
};
const alternateIdentities = {
  HODLXXI_OAUTH_CLIENT_ID: "client_social_production_v1",
  SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID: "social-production-session-issuance-service-v1",
  SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_ID: "social-production-mobile-authorization-service-v1"
};
// Test-only infrastructure objects; no key is exported or written to disk.
const rsaKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const bomb = () => assert.fail("unexpected file or network access");
function fakeLoader(key = rsaKey, info = {}) {
  const calls = [];
  return {
    calls,
    async openFile(path, flags) {
      calls.push({ path, flags });
      let used = false;
      return {
        async stat() { return { isFile: () => true, mode: 0o600, size: 1, ...info }; },
        async read(bytes, offset) { if (used) return { bytesRead: 0 }; bytes[offset] = 120; used = true; return { bytesRead: 1 }; },
        async close() { calls.push("closed"); }
      };
    },
    parseKey(bytes) { assert.ok(Buffer.isBuffer(bytes)); return key; },
    clientDependencies: { requestImpl: bomb }
  };
}
function dependencies(config) {
  return {
    config, sessions: (config.mobile.enabled ? createSessionStore : createBoundedStore)({ ttlSeconds: 3600, capacity: 10 }),
    pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10 }),
    oauthClient: { buildAuthorizationUrl: bomb, exchangeCode: bomb }, authorityReader: async () => ({ status: "Limited" })
  };
}
const request = (url, method = "GET") => ({ url, method, headers: {} });

test("absent/false issuance ignores all key paths and preserves old BFF responses", async () => {
  for (const enabled of [undefined, "false"]) {
    const config = configFromEnvironment({ ...env, ...issuanceEnv, SOCIAL_UBID_SESSION_ISSUANCE_ENABLED: enabled });
    assert.deepEqual(config.sessionIssuance, { enabled: false });
    const deps = dependencies(config);
    const composed = await createSocialMobileRuntime(deps, { openFile: bomb, clientFactory: bomb });
    const ordinary = createSocialOAuthBff(deps);
    assert.deepEqual(composed.mobilePostRoutes, []);
    for (const url of ["/auth/session", "/auth/health", "/auth/social-read-config", "/auth/mobile/v1/context"]) {
      assert.deepEqual(await composed.bff(request(url)), await ordinary(request(url)));
    }
  }
});

for (const name of Object.keys(issuanceEnv).filter((name) => !name.endsWith("_ENABLED"))) {
  test("enabled issuance requires " + name, () => {
    const incomplete = { ...env, ...issuanceEnv }; delete incomplete[name];
    assert.throws(() => configFromEnvironment(incomplete), /invalid Social OAuth configuration/);
  });
}
for (const origin of ["http://identity.example", "https://IDENTITY.example", "https://identity.example/", "https://identity.example/path", "https://u:p@identity.example", "https://identity.example?x=1", "https://identity.example.", "https://other.example"]) {
  test("reject noncanonical or mismatched issuer " + origin, () => assert.throws(() => configFromEnvironment({ ...env, ...issuanceEnv, SOCIAL_UBID_SESSION_ISSUANCE_ISSUER_ORIGIN: origin })));
}
for (const socket of ["relative.sock", "/tmp//a.sock", "/tmp/../a.sock", "/tmp/./a.sock", "/", "/tmp/a.sock/", "https://identity.example", "/tmp/a sock", "/" + "a".repeat(107)]) {
  test("reject invalid socket " + socket, () => assert.throws(() => configFromEnvironment({ ...env, ...issuanceEnv, SOCIAL_UBID_SESSION_ISSUANCE_PRIVATE_SOCKET_PATH: socket })));
}
for (const field of ["SERVICE_CLIENT_ID", "SERVICE_CLIENT_SIGNING_KEY_ID"]) {
  for (const value of ["", " bad", "bad/key", "bad key", "a".repeat(256)]) {
    test("reject invalid " + field + " " + JSON.stringify(value), () => assert.throws(() => configFromEnvironment({ ...env, ...issuanceEnv, ["SOCIAL_UBID_SESSION_ISSUANCE_" + field]: value })));
  }
}
for (const value of ["249", "5001", "1.5", "true"]) {
  test("enforce existing client timeout " + value, () => assert.throws(() => configFromEnvironment({ ...env, ...issuanceEnv, SOCIAL_UBID_SESSION_ISSUANCE_TIMEOUT_MS: value })));
}

test("key loading yields exact injected client config and closes the file", async () => {
  const config = configFromEnvironment({ ...env, ...issuanceEnv }).sessionIssuance;
  const loader = fakeLoader();
  let received;
  const result = await createSessionServiceIntegration(config, { ...loader, clientFactory(c, d) { received = c; assert.equal(d, loader.clientDependencies); return "synthetic-client"; } });
  assert.equal(result, "synthetic-client");
  assert.deepEqual(received, {
    enabled: true, issuerOrigin: "https://identity.example", socketPath: "/tmp/synthetic-issuance.sock",
    clientId: "social-staging-session-issuance-service-v1", clientSigningKeyId: "synthetic-service-key",
    signingKey: rsaKey, timeoutMs: 1000
  });
  assert.equal(loader.calls[0].path, config.signingKeyPath); assert.equal(loader.calls[1], "closed");
  assert.equal(Object.hasOwn(config, "signingKey"), false);
});

test("missing and disabled integrations never call loader or factory", async () => {
  for (const config of [undefined, {}, { enabled: false }]) assert.equal(await createSessionServiceIntegration(config, { openFile: bomb, clientFactory: bomb }), undefined);
});

for (const [name, key] of [
  ["RSA1024", generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey],
  ["EC", generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey],
  ["public", generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey],
  ["string", "not-a-KeyObject"]
]) {
  test("reject unsupported signing key " + name, async () => {
    const loader = fakeLoader(key);
    await assert.rejects(createSessionServiceIntegration(configFromEnvironment({ ...env, ...issuanceEnv }).sessionIssuance, { ...loader, clientFactory: bomb }), /invalid mobile session configuration/);
    assert.equal(loader.calls.at(-1), "closed");
  });
}
for (const info of [{ mode: 0o644 }, { size: 16385 }, { size: 0 }, { isFile: () => false }]) {
  test("reject unsafe signing file " + JSON.stringify(info), async () => {
    const loader = fakeLoader(rsaKey, info);
    await assert.rejects(createSessionServiceIntegration(configFromEnvironment({ ...env, ...issuanceEnv }).sessionIssuance, { ...loader, parseKey: bomb, clientFactory: bomb }));
    assert.equal(loader.calls.at(-1), "closed");
  });
}

test("issuance enabled alone constructs client but keeps mobile composition off", async () => {
  const config = configFromEnvironment({ ...env, ...issuanceEnv });
  const loader = fakeLoader();
  const composed = await createSocialMobileRuntime(dependencies(config), loader);
  assert.deepEqual(composed.mobilePostRoutes, []); assert.equal(composed.manager, undefined);
  assert.equal(loader.calls.length, 2);
});

test("direct trusted runtime rejects malformed identities and origin disagreement before reading keys", async () => {
  const config = configFromEnvironment({ ...env, ...issuanceEnv, ...mobileEnv });
  for (const changed of [
    { ...config, authorityOrigin: "https://other.example" },
    { ...config, clientId: "invalid viewer" },
    { ...config, sessionIssuance: { ...config.sessionIssuance, clientId: "invalid/backend" } },
    { ...config, sessionIssuance: { enabled: false } }
  ]) await assert.rejects(createSocialMobileRuntime(dependencies(changed), { openFile: bomb }));
});

for (const [name, identities] of [["staging", {}], ["production-style", alternateIdentities]]) {
  test("explicit " + name + " identities compose without environment policy", async () => {
    const input = { ...env, ...issuanceEnv, ...mobileEnv, ...identities };
    const config = configFromEnvironment(input);
    let clientId;
    const composed = await createSocialMobileRuntime(dependencies(config), {
      ...fakeLoader(), clientFactory(value, deps) {
        clientId = value.clientId;
        return createUbidSessionIssuanceClient(value, deps);
      }
    });
    assert.equal(clientId, input.SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID);
    assert.equal(config.clientId, input.HODLXXI_OAUTH_CLIENT_ID);
    assert.equal(config.mobile.clientId, input.SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_ID);
    assert.ok(composed.mobilePostRoutes.includes("/auth/mobile/v1/session/issue"));
  });
}

for (const field of ["HODLXXI_OAUTH_CLIENT_ID", "SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID", "SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_ID"]) {
  test("explicit identity has no default: " + field, () => {
    const input = { ...env, ...issuanceEnv, ...mobileEnv }; delete input[field];
    assert.throws(() => configFromEnvironment(input));
  });
  for (const value of [null, "", "bad/name", "bad name", "bad\nname", "é", "a".repeat(256), true]) {
    test("malformed configured identity " + field + ": " + JSON.stringify(value), () => {
      assert.throws(() => configFromEnvironment({ ...env, ...issuanceEnv, ...mobileEnv, [field]: value }));
    });
  }
}

test("browser and request identity overrides are rejected without upstream calls", async () => {
  const config = configFromEnvironment({ ...env, ...issuanceEnv, ...mobileEnv, ...alternateIdentities });
  let upstreamCalls = 0;
  const loader = { ...fakeLoader(), clientDependencies: { requestImpl() {
    upstreamCalls++; throw Error("unexpected upstream request");
  } } };
  const composed = await createSocialMobileRuntime(dependencies(config), loader);
  const headers = { host: "social.example", origin: config.publicOrigin, "content-type": "application/json" };
  for (const field of ["clientId", "backendId", "servicePrincipal", "client_id", "backend_id", "service_principal"]) {
    const response = await composed.bff({ method: "POST", url: "/auth/mobile/v1/context", headers,
      body: JSON.stringify({ [field]: "request-selected-identity" }) });
    assert.equal(response.status, 503);
    assert.equal(response.headers["Set-Cookie"], undefined);
    const client = await createSessionServiceIntegration(config.sessionIssuance, loader);
    await assert.rejects(client.revoke({ body: { issuanceId: "a".repeat(64), [field]: "request-selected-identity" }, viewerAccessToken: "synthetic.viewer.token" }));
  }
  assert.equal(config.sessionIssuance.clientId, alternateIdentities.SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID);
  assert.equal(config.clientId, alternateIdentities.HODLXXI_OAUTH_CLIENT_ID);
  assert.equal(upstreamCalls, 0);
});

test("mobile has its own complete explicit enable boundary", async () => {
  for (const values of [{ ...env, SOCIAL_MOBILE_ENABLED: "true" }, { ...env, ...mobileEnv }, { ...env, ...issuanceEnv, SOCIAL_MOBILE_ENABLED: "true" }]) assert.throws(() => configFromEnvironment(values));
  const config = configFromEnvironment({ ...env, ...issuanceEnv, ...mobileEnv });
  const composed = await createSocialMobileRuntime(dependencies(config), fakeLoader());
  assert.ok(composed.mobilePostRoutes.includes("/auth/mobile/v1/session/issue"));
  assert.equal(typeof composed.capabilitySessionReader, "function");
  assert.equal(typeof createHttpHandler({ publicOrigin: config.publicOrigin, ...composed }), "function");
});

test("configured real client uses only exact Unix request, with no fallback on failure", async () => {
  const config = configFromEnvironment({ ...env, ...issuanceEnv }).sessionIssuance;
  let requests = 0;
  const loader = fakeLoader();
  const client = await createSessionServiceIntegration(config, {
    ...loader,
    clientDependencies: { requestImpl(options) {
      requests++;
      assert.equal(options.socketPath, config.socketPath);
      assert.equal(options.path, "/internal/v1/social/session-issuance/service-token");
      assert.equal(options.headers.Host, "identity.example");
      for (const name of ["hostname", "host", "port", "lookup", "protocol"]) assert.equal(Object.hasOwn(options, name), false);
      const outgoing = new EventEmitter(); outgoing.destroy = () => {};
      outgoing.end = () => queueMicrotask(() => outgoing.emit("error", Error("synthetic offline failure")));
      return outgoing;
    } }
  });
  await assert.rejects(client.revoke({ body: { issuanceId: "a".repeat(64) }, viewerAccessToken: "synthetic.viewer.token" }));
  assert.equal(requests, 1);
  assert.equal(client.serviceToken, undefined);
});

test("ordinary CLI default off starts with fake listener; invalid enabled config fails before listen", async () => {
  const signals = ["SIGINT", "SIGTERM"];
  const before = signals.map((name) => new Set(process.listeners(name)));
  let starts = 0;
  try {
    const code = await runServer({ env, stdout() {}, stderr: bomb, createServer(handler) {
      starts++; assert.equal(typeof handler, "function");
      return { once() {}, listen(port, host, cb) { assert.equal(host, "127.0.0.1"); cb(); }, close() {} };
    } });
    assert.equal(code, 0); assert.equal(starts, 1);
    const errors = [];
    const invalid = await runServer({ env: { ...env, SOCIAL_UBID_SESSION_ISSUANCE_ENABLED: "true" }, stderr: (s) => errors.push(s), createServer: bomb });
    assert.equal(invalid, 2); assert.deepEqual(errors, ["invalid configuration"]);
  } finally {
    signals.forEach((name, i) => { for (const fn of process.listeners(name)) if (!before[i].has(fn)) process.removeListener(name, fn); });
  }
});

test("enabled CLI supplies the mobile session store and HTTP routes without a live listener", async () => {
  const signals = ["SIGINT", "SIGTERM"];
  const before = signals.map((name) => new Set(process.listeners(name)));
  let handler;
  try {
    const code = await runServer({
      env: { ...env, ...issuanceEnv, ...mobileEnv }, stdout() {}, stderr: bomb,
      async mobileRuntimeFactory(deps) {
        assert.equal(typeof deps.sessions.beginLogout, "function");
        return createSocialMobileRuntime(deps, fakeLoader());
      },
      createServer(value) {
        handler = value;
        return { once() {}, listen(port, host, done) { done(); }, close() {} };
      }
    });
    assert.equal(code, 0);
    const incoming = Readable.from([Buffer.from("{}")]);
    Object.assign(incoming, { method: "POST", url: "/auth/mobile/v1/context", headers: {
      host: "social.example", origin: "https://social.example", "content-type": "application/json", "content-length": "2"
    } });
    incoming.rawHeaders = Object.entries(incoming.headers).flat();
    const response = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(body) { this.body = body; } };
    await handler(incoming, response);
    assert.equal(response.statusCode, 200);
    assert.doesNotMatch(response.body, /signingKey|PRIVATE|service-token/);
  } finally {
    signals.forEach((name, i) => { for (const fn of process.listeners(name)) if (!before[i].has(fn)) process.removeListener(name, fn); });
  }
});

test("capability integration forwards the exact current mobile session reader", () => {
  const sessionReader = () => null;
  let calls = 0;
  createRecipientCapabilityIntegration({ enabled: true }, {
    sessions: {}, authorityReader() {}, fullDirectoryClient: { readForViewer() {} }, sessionReader,
    storeFactory: () => ({}),
    issuerFactory(options) { calls++; assert.equal(options.sessionReader, sessionReader); return { issue() {} }; },
    resolverFactory(options) { calls++; assert.equal(options.sessionReader, sessionReader); return { resolve() {} }; }
  });
  assert.equal(calls, 2);
});

test("browser import graph never includes server configuration or key loader", () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const visited = new Set();
  function visit(path) {
    if (visited.has(path)) return; visited.add(path);
    assert.ok(!path.startsWith(resolve(root, "src/server") + "/"), path);
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, /SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_SIGNING_KEY_PATH|social-mobile-runtime-v1|BEGIN PRIVATE KEY/);
    for (const match of source.matchAll(/(?:from\s*|import\s*\()\s*["'](\.[^"']+)["']/g)) {
      if (match[1].endsWith(".mjs") || match[1].endsWith(".js")) visit(resolve(dirname(path), match[1]));
    }
  }
  for (const file of readdirSync(resolve(root, "web"))) if (file.endsWith(".mjs")) visit(resolve(root, "web", file));
});
