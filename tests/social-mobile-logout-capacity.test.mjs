import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSessionStore, createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { createSocialMobileComposition } from "../src/server/social-mobile-composition-v1.mjs";
import { createHttpHandler } from "../scripts/hodlxxi-social-server.mjs";
import { MOBILE_COMMANDS } from "../web/social-mobile-protocol-v1.mjs";

const subject = "a".repeat(64);
const start = Date.parse("2030-01-01T00:00:00Z");
const config = { publicOrigin: "https://social.example", authorityOrigin: "https://identity.example", clientId: "social",
  callbackUri: "https://social.example/auth/callback", scope: "openid profile", transactionTtlSeconds: 300, sessionTtlSeconds: 3600 };
const invalidated = { schema: "hodlxxi.social_mobile_generation_invalidation.v1", version: 1, status: "invalidated" };
function fixture(capacity = 1, storeCapacity = capacity + 4) {
  let time = start, sequence = 0, failRemote = false, holdResolve = null;
  const calls = [], credentials = new Map();
  const sessions = createSessionStore({ ttlSeconds: 3600, capacity: storeCapacity, now: () => time });
  const pendingTransactions = createBoundedStore({ ttlSeconds: 300, capacity: 10, now: () => time });
  const mobileClient = Object.fromEntries(Object.keys(MOBILE_COMMANDS).map((name) => [name, async () => { throw Error("unexpected mobile operation: " + name); }]));
  mobileClient.oauthInvalidate = async ({ viewerAccessToken }) => {
    calls.push(viewerAccessToken); if (failRemote) throw Error("synthetic unconfirmed revoke"); return invalidated;
  };
  const issuanceClient = {
    async issue() { throw Error("not used"); }, async recover() { throw Error("not used"); },
    async resolve({ viewerAccessToken }) {
      const r = credentials.get(viewerAccessToken); assert.ok(r);
      if (holdResolve) { holdResolve.started(); await holdResolve.promise; }
      return { receipt: r.receipt, subject, currentActive: true };
    },
    async revoke({ body, viewerAccessToken }) {
      calls.push(viewerAccessToken); if (failRemote) throw Error("synthetic unconfirmed revoke");
      return { schema: "hodlxxi.social_session_revocation.v1", version: 1, issuanceId: body.issuanceId, status: "revoked" };
    }
  };
  const composition = createSocialMobileComposition({ enabled: true, config, sessions, pendingTransactions, oauthClient: {},
    mobileClient, issuanceClient, capacity, now: () => time });
  async function add(kind, id = "target") {
    const token = "synthetic." + (++sequence) + ".credential";
    if (kind === "desktop") { assert.equal(sessions.create(id, { subject, viewerAccessToken: token }), true); return { id, token }; }
    const receipt = { schema: "hodlxxi.social_session_issuance.v1", version: 1, issuanceId: sequence.toString(16).padStart(64, "0"),
      issuedAt: "2030-01-01T00:00:00Z", expiresAt: "2030-01-01T00:03:00Z" };
    const result = { receipt, subject, viewerAccessToken: token, currentActive: true }; credentials.set(token, result);
    const presentation = await composition.manager.install(result, { subject, expiresAt: start + 180000, stillCurrent: () => true });
    return { id: presentation.id, token, result };
  }
  return { ...composition, sessions, calls, add, mobileClient, issuanceClient,
    fail: (v) => { failRemote = v; }, tick: (ms) => { time += ms; },
    hold: (v) => { holdResolve = v; }, now: () => time };
}
async function fill(f, count, unconfirmed) {
  f.fail(unconfirmed);
  for (let n = 0; n < count; n++) {
    const old = await f.add("desktop", "old-" + n);
    if (unconfirmed) await assert.rejects(f.manager.logout(old.id)); else assert.equal(await f.manager.logout(old.id), true);
  }
}
async function endpoint(t, f) {
  const root = await mkdtemp(join(tmpdir(), "logout-capacity-"));
  const socketPath = join(root, "test.sock");
  const server = http.createServer(createHttpHandler({ publicOrigin: config.publicOrigin, bff: f.bff, mobilePostRoutes: f.mobilePostRoutes }));
  server.listen(socketPath); await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); await rm(root, { recursive: true }); });
  return (path, method, cookie, csrf, origin = config.publicOrigin) => new Promise((resolve, reject) => {
    const body = method === "POST" ? "{}" : undefined;
    const request = http.request({ socketPath, path, method, agent: false, headers: {
      Host: "social.example", Origin: origin, Cookie: cookie,
      ...(body === undefined ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }),
      ...(csrf ? { "x-hodlxxi-mobile-csrf": csrf } : {})
    } }, (response) => {
      const chunks = []; response.on("data", (chunk) => chunks.push(chunk)); response.on("error", reject);
      response.on("end", () => resolve({ status: response.statusCode, headers: response.headers, json: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    request.on("error", reject); request.setTimeout(4000, () => request.destroy(Error("test request timed out"))); request.end(body);
  });
}
for (const capacity of [1, 1024]) for (const pending of [false, true]) for (const kind of ["desktop", "mobile"]) {
  test(`HTTP same-cookie logout denies ${kind}, capacity=${capacity}, prior-pending=${pending}`, { timeout: 15000 }, async (t) => {
    const f = fixture(capacity); await fill(f, capacity, pending); const target = await f.add(kind);
    const send = await endpoint(t, f), originalCookie = "__Host-hodlxxi-social-session=" + target.id;
    const boot = await send("/auth/mobile/v1/context", "POST", originalCookie);
    assert.equal(boot.status, 200);
    const cookie = originalCookie + "; " + boot.headers["set-cookie"].at(-1).split(";")[0], csrf = boot.json.csrf;
    const out = await send("/auth/logout", "POST", cookie, csrf);
    // Test the actual invariant first: no successful cookie replay after accepted local logout.
    const check = await send("/auth/session", "GET", originalCookie);
    assert.equal(check.status, 200); assert.deepEqual(check.json, { authenticated: false });
    assert.equal(await f.manager.read(target.id), null); assert.equal(f.sessions.get(target.id), null);
    assert.equal(await f.capabilitySessionReader(target.id), null);
    assert.equal((await send("/auth/social-read-config", "GET", originalCookie)).status, 401);
    assert.equal(out.status, pending ? 503 : 200); assert.equal(out.json.logout, pending ? "pending" : "confirmed");
    assert.equal(f.calls.filter((c) => c === target.token).length, 1);
    const replacement = await f.add("desktop", "replacement");
    f.fail(false);
    const retry = await send("/auth/logout", "POST", cookie, csrf);
    assert.equal(retry.status, 200); assert.equal(retry.json.logout, "confirmed");
    const callsAfterAck = f.calls.length;
    assert.equal((await send("/auth/logout", "POST", cookie, csrf)).status, 200);
    assert.equal(f.calls.length, callsAfterAck); // Idempotent acknowledgement, same original credential.
    assert.equal((await f.manager.read(replacement.id)).viewerAccessToken, replacement.token);
    f.tick(300001);
    assert.equal(await f.manager.read(target.id), null); assert.equal(f.sessions.get(target.id), null);
    assert.ok(f.sessions.size <= capacity + 4);
  });
}
for (const pending of [false, true]) test(`in-flight mobile resolve cannot cross overflow logout; prior-pending=${pending}`, async () => {
  const f = fixture(); await fill(f, 1, pending); const target = await f.add("mobile");
  let release, started; const ready = new Promise((r) => { started = r; }); const promise = new Promise((r) => { release = r; });
  f.hold({ promise, started }); const read = f.manager.read(target.id); await ready;
  f.fail(true);
  try { await assert.rejects(f.manager.logout(target.id)); } finally { release(); }
  assert.equal(await read, null); f.hold(null);
  assert.equal(await f.manager.read(target.id), null);
  f.fail(false); assert.equal(await f.manager.logout(target.id), true);
});
test("lock-capacity failure still denies and preserves bounded exact retry", async () => {
  const f = fixture(); const target = await f.add("desktop");
  let release, entered; const ready = new Promise((r) => { entered = r; }); const wait = new Promise((r) => { release = r; });
  const busy = f.manager.serial("unrelated", async () => { entered(); await wait; }); await ready;
  try { await assert.rejects(f.manager.logout(target.id)); assert.equal(await f.manager.read(target.id), null); }
  finally { release(); await busy; }
  assert.equal(f.calls.length, 0); assert.equal(await f.manager.logout(target.id), true); assert.deepEqual(f.calls, [target.token]);
});
test("overflow retry expiry removes denial record rather than resurrecting desktop authentication", async () => {
  const f = fixture(); await fill(f, 1, true); const target = await f.add("desktop");
  await assert.rejects(f.manager.logout(target.id));
  assert.equal(f.sessions.getForLogout(target.id).viewerAccessToken, target.token);
  f.tick(299999); await assert.rejects(f.manager.logout(target.id)); assert.equal(await f.manager.read(target.id), null);
  f.tick(2); assert.equal(f.sessions.getForLogout(target.id), null); assert.equal(await f.manager.read(target.id), null);
  await assert.rejects(f.manager.logout(target.id)); assert.equal(f.sessions.size, 0);
});
test("concurrent overflow retries confirm one original cancellation without issuing anything", async () => {
  const f = fixture(); await fill(f, 1, true); const target = await f.add("desktop");
  await assert.rejects(f.manager.logout(target.id)); f.fail(false);
  const before = f.calls.filter((c) => c === target.token).length;
  assert.deepEqual(await Promise.all([f.manager.logout(target.id), f.manager.logout(target.id), f.manager.logout(target.id)]), [true, true, true]);
  assert.equal(f.calls.filter((c) => c === target.token).length, before + 1); assert.equal(await f.manager.read(target.id), null);
});
test("unconfirmed overflow is bounded by existing session slots, not an unbounded denial map", async () => {
  const f = fixture(1, 3); await fill(f, 1, true);
  for (const id of ["second", "third"]) { await f.add("desktop", id); await assert.rejects(f.manager.logout(id)); assert.equal(await f.manager.read(id), null); }
  assert.equal(f.sessions.size, 3); assert.equal(f.sessions.create("fourth", { subject, viewerAccessToken: "other.test.token" }), false);
  f.tick(300001); assert.equal(f.sessions.size, 0);
});
test("same issuance cannot be reinstalled after an unconfirmed overflow logout", async () => {
  const f = fixture(); await fill(f, 1, true); const target = await f.add("mobile");
  await assert.rejects(f.manager.logout(target.id));
  await assert.rejects(f.manager.install(target.result, { subject, expiresAt: start + 180000, stillCurrent: () => true }));
  assert.equal(await f.manager.read(target.id), null);
});
test("store active/pending OAuth behavior is unchanged until explicit logout", () => {
  const store = createSessionStore({ ttlSeconds: 3600, capacity: 2, now: () => start });
  assert.equal(store.create("desktop", { subject, viewerAccessToken: "normal.browser.token" }), true);
  const original = store.get("desktop"); assert.equal(original.subject, subject); assert.equal(Object.isFrozen(original), true);
  assert.equal(store.consumeIf("desktop", () => false), null); assert.equal(store.get("desktop"), original);
  assert.equal(store.consume("desktop"), original); assert.equal(store.get("desktop"), null);
  const pending = createBoundedStore({ ttlSeconds: 60, capacity: 2, now: () => start });
  assert.equal(pending.create("oauth", { state: "unchanged" }), true); assert.equal(pending.consume("oauth").state, "unchanged");
});
for (const deniedRequest of ["origin", "csrf"]) test(`capacity does not weaken ${deniedRequest} checks`, async (t) => {
  const f = fixture(); await fill(f, 1, true); const target = await f.add("desktop");
  const send = await endpoint(t, f), originalCookie = "__Host-hodlxxi-social-session=" + target.id;
  const boot = await send("/auth/mobile/v1/context", "POST", originalCookie);
  const cookie = originalCookie + "; " + boot.headers["set-cookie"].at(-1).split(";")[0];
  const out = await send("/auth/logout", "POST", cookie,
    deniedRequest === "csrf" ? "incorrect" : boot.json.csrf,
    deniedRequest === "origin" ? "https://foreign.example" : config.publicOrigin);
  assert.notEqual(out.status, 200);
  assert.equal((await send("/auth/session", "GET", originalCookie)).json.authenticated, true);
  assert.equal(f.calls.filter((c) => c === target.token).length, 0);
});
test("expired mobile credential remains cancellation-only under full retry bookkeeping", async () => {
  const f = fixture(); await fill(f, 1, true); const target = await f.add("mobile");
  f.tick(180001); assert.equal(await f.manager.read(target.id), null);
  await assert.rejects(f.manager.logout(target.id));
  assert.equal(f.sessions.getForLogout(target.id).viewerAccessToken, target.token);
  f.fail(false); assert.equal(await f.manager.logout(target.id), true);
  assert.equal(await f.manager.read(target.id), null);
});
test("disabled composition retains normal desktop logout without calling mobile upstream", async () => {
  const f = fixture(); const target = await f.add("desktop");
  const off = createSocialMobileComposition({ enabled: false, config, sessions: f.sessions,
    pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10 }), oauthClient: {},
    mobileClient: f.mobileClient, issuanceClient: f.issuanceClient });
  const cookie = "__Host-hodlxxi-social-session=" + target.id;
  assert.equal(JSON.parse((await off.bff({ method: "GET", url: "/auth/session", headers: { cookie } })).body).authenticated, true);
  assert.equal((await off.bff({ method: "POST", url: "/auth/logout", headers: { cookie, origin: config.publicOrigin } })).status, 200);
  assert.equal(JSON.parse((await off.bff({ method: "GET", url: "/auth/session", headers: { cookie } })).body).authenticated, false);
  assert.equal(f.calls.length, 0);
});
