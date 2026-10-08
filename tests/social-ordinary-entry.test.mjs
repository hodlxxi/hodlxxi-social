import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createSocialEntryActions } from "../web/social-entry-actions-v1.mjs";
import { bindAuthenticatedEntry } from "../web/auth-entry.mjs";
import { createSocialMobileComposition } from "../src/server/social-mobile-composition-v1.mjs";
import { createBoundedStore, createSessionStore } from "../src/server/social-oauth-memory.mjs";
import { MOBILE_COMMANDS } from "../web/social-mobile-protocol-v1.mjs";

const config = { publicOrigin: "https://social.example", authorityOrigin: "https://identity.example", clientId: "social",
  callbackUri: "https://social.example/auth/callback", scope: "openid", transactionTtlSeconds: 300, sessionTtlSeconds: 1800 };
const subject = "a".repeat(64);
const ingress = JSON.parse(readFileSync(new URL("./fixtures/social_mobile_authorization_ingress_v1.json", import.meta.url)));

function fixture(enabled = true, capacity = 10) {
  let time = Date.parse("2030-01-01T00:00:00Z"), failLogout = false, upstreamCalls = 0;
  const now = () => time, jar = new Map(), requests = [];
  const sessions = createSessionStore({ ttlSeconds: 1800, capacity: 10, now });
  const mobileClient = Object.fromEntries(Object.keys(MOBILE_COMMANDS).map((name) => [name, async () => assert.fail("unexpected upstream: " + name)]));
  mobileClient.qrOffer = async () => JSON.parse(ingress.offer);
  mobileClient.oauthInvalidate = async () => {
    upstreamCalls++;
    if (failLogout) throw Error("synthetic private upstream failure");
    return { schema: "hodlxxi.social_mobile_generation_invalidation.v1", version: 1, status: "invalidated" };
  };
  const issuanceClient = Object.fromEntries(["issue", "recover", "resolve", "revoke"].map((name) => [name, async () => assert.fail("unexpected issuance: " + name)]));
  const composition = createSocialMobileComposition({ enabled, config, sessions, capacity, now,
    pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 50, now }), mobileClient, issuanceClient,
    oauthClient: { authenticate: async () => ({ subject, accessToken: "synthetic.viewer.token" }) } });
  const cookie = () => [...jar].map(([k, v]) => k + "=" + v).join("; ");
  const apply = (result) => {
    const headers = result.headers["Set-Cookie"];
    for (const value of headers === undefined ? [] : Array.isArray(headers) ? headers : [headers]) {
      const pair = value.split(";", 1)[0], split = pair.indexOf("="), key = pair.slice(0, split);
      if (value.includes("Max-Age=0;")) jar.delete(key); else jar.set(key, pair.slice(split + 1));
    }
    return result;
  };
  const send = async (url, method = "GET", body, extra = {}) => apply(await composition.bff({ url, method,
    headers: { cookie: cookie(), origin: config.publicOrigin, ...(body === undefined ? {} : { "content-type": "application/json" }), ...extra }, body }));
  const fetchImpl = async (url, init) => {
    requests.push({ url, ...init });
    const result = await send(url, init.method, init.body, Object.fromEntries(Object.entries(init.headers).map(([k, v]) => [k.toLowerCase(), v])));
    return new Response(result.body, { status: result.status, headers: result.headers });
  };
  const actions = () => createSocialEntryActions({ fetchImpl });
  async function start() {
    assert.equal(await actions().login(), "/auth/login");
    const result = await send("/auth/login");
    assert.equal(result.status, 302);
    const target = new URL(result.headers.Location);
    assert.equal(target.origin, config.authorityOrigin);
    assert.equal(target.pathname, "/oauth/authorize");
    return { cookie: cookie(), state: target.searchParams.get("state") };
  }
  async function finish(transaction) {
    return send("/auth/callback?code=synthetic-code&state=" + transaction.state);
  }
  return { ...composition, sessions, jar, cookie, send, fetchImpl, actions, start, finish, requests,
    advance: (ms) => { time += ms; }, failLogout: (value) => { failLogout = value; }, calls: () => upstreamCalls };
}

for (const enabled of [false, true]) test(`ordinary entry and logout use the configured mode: ${enabled}`, async () => {
  const f = fixture(enabled), transaction = await f.start();
  assert.equal(f.sessions.size, 0); // Preparing a context and redirect grants no session.
  assert.equal((await f.finish(transaction)).status, 303);
  assert.deepEqual(JSON.parse((await f.send("/auth/session")).body), { authenticated: true, subject });
  const oldCookie = f.cookie();
  assert.deepEqual(await f.actions().logout(), { authenticated: false });
  assert.deepEqual(JSON.parse((await f.send("/auth/session", "GET", undefined, { cookie: oldCookie })).body), { authenticated: false });
  assert.equal(f.calls(), enabled ? 1 : 0);
  assert.equal(f.requests.filter((r) => r.url.endsWith("/context")).length, enabled ? 2 : 0);
  for (const request of f.requests) {
    assert.equal(request.credentials, "same-origin"); assert.equal(request.redirect, "error");
    assert.equal(request.cache, "no-store"); assert.ok(request.signal instanceof AbortSignal);
  }
  // A complete sign-out can immediately be followed by a fresh sign-in.
  assert.equal((await f.finish(await f.start())).status, 303);
});

test("cancelled login can restart immediately and invalidates its original context", async () => {
  const f = fixture(true, 1), first = await f.start();
  const second = await f.start();
  const stale = await f.bff({ method: "GET", url: "/auth/callback?code=synthetic-old&state=" + first.state, headers: { cookie: first.cookie } });
  assert.equal(stale.status, 409); assert.equal(f.sessions.size, 0);
  assert.equal((await f.finish(second)).status, 303);
});

test("expired context and stale post-restart cookies permit a fresh ordinary login", async () => {
  const f = fixture(); await f.start(); f.advance(600001);
  assert.equal((await f.finish(await f.start())).status, 303);
  const restarted = fixture();
  for (const [key, value] of f.jar) restarted.jar.set(key, value);
  assert.equal((await restarted.finish(await restarted.start())).status, 303);
});

test("entry context does not replace a current authenticated session", async () => {
  const f = fixture(); await f.finish(await f.start()); const before = f.cookie();
  await assert.rejects(f.actions().login(), /Social entry unavailable/);
  assert.equal(f.cookie(), before); assert.equal(f.sessions.size, 1);
});

test("pending logout stays denied and supports retry after page reload", async () => {
  const f = fixture(); await f.finish(await f.start()); const oldCookie = f.cookie();
  f.failLogout(true); await assert.rejects(f.actions().logout(), /Social entry unavailable/);
  assert.equal(JSON.parse((await f.send("/auth/session", "GET", undefined, { cookie: oldCookie })).body).authenticated, false);
  await assert.rejects(f.actions().login(), /Social entry unavailable/);
  f.failLogout(false);
  assert.deepEqual(await f.actions().logout(), { authenticated: false });
  assert.equal((await f.finish(await f.start())).status, 303);
});

test("ordinary login preserves a pending phone pairing context", async () => {
  const f = fixture();
  const boot = await f.send("/auth/mobile/v1/context", "POST", "{}");
  const csrf = JSON.parse(boot.body).csrf;
  const offer = JSON.parse(ingress.offer);
  const phase1 = JSON.parse(readFileSync(new URL("./fixtures/social_mobile_device_authorization_v1.json", import.meta.url)));
  const qr = "hodlxxi-social-pair:v1:" + offer.pairingId + ":" + phase1.pairingSecret;
  assert.equal(typeof qr, "string");
  const result = await f.send("/auth/mobile/v1/qr/offer", "POST", JSON.stringify({ qr }), { "x-hodlxxi-mobile-csrf": csrf });
  assert.equal(result.status, 200); assert.equal(JSON.parse(result.body).pairingId, offer.pairingId);
  const before = f.cookie(); await assert.rejects(f.actions().login(), /Social entry unavailable/);
  assert.equal(f.cookie(), before);
});

test("context purpose requires an exact body and same origin", async () => {
  const f = fixture();
  for (const body of ['{"purpose":"other"}', '{"purpose":"login","extra":true}', '{"purpose":null}', '{"purpose":true}']) {
    assert.notEqual((await f.send("/auth/mobile/v1/context", "POST", body)).status, 200);
  }
  assert.equal((await f.send("/auth/mobile/v1/context", "POST", '{"purpose":"login"}', { origin: "https://foreign.example" })).status, 403);
  assert.equal((await f.send("/auth/login")).status, 409);
  assert.equal((await f.send("/auth/entry-config?override=true")).status, 400);
  assert.equal((await f.send("/auth/entry-config", "POST")).status, 405);
});

test("wrong logout CSRF never signs out the current session", async () => {
  const f = fixture(); await f.finish(await f.start());
  await f.send("/auth/mobile/v1/context", "POST", '{"purpose":"logout"}');
  assert.notEqual((await f.send("/auth/logout", "POST", "{}", { "x-hodlxxi-mobile-csrf": "0".repeat(64) })).status, 200);
  assert.equal(JSON.parse((await f.send("/auth/session")).body).authenticated, true);
  assert.equal(f.calls(), 0);
});

test("failed configuration never falls back to unguarded navigation", async () => {
  for (const response of [new Response("{}", { status: 503 }), new Response('{"mobileContextRequired":"false"}', { headers: { "Content-Type": "application/json" } }),
    new Response('{"mobileContextRequired":false,"extra":true}', { headers: { "Content-Type": "application/json" } }),
    new Response("x".repeat(1025), { headers: { "Content-Type": "application/json" } }), new Response("<html>")]) {
    let calls = 0;
    const actions = createSocialEntryActions({ fetchImpl: async () => { calls++; return response; } });
    await assert.rejects(actions.login(), /Social entry unavailable/); assert.equal(calls, 1);
  }
});

test("one controller admits only one concurrent entry action", async () => {
  let release;
  const actions = createSocialEntryActions({ fetchImpl: () => new Promise((resolve) => { release = resolve; }) });
  const first = actions.login();
  await assert.rejects(actions.login(), /Social entry unavailable/);
  release(new Response('{"mobileContextRequired":false}', { headers: { "Content-Type": "application/json" } }));
  assert.equal(await first, "/auth/login");
});

test("entry fetch is aborted at its deadline without exposing the underlying error", async () => {
  const actions = createSocialEntryActions({ timeoutMs: 5, fetchImpl: (_path, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(Error("synthetic private diagnostic")), { once: true });
  }) });
  await assert.rejects(actions.login(), /^Error: Social entry unavailable$/);
});

test("the real entry button prepares context and navigates without a signer or storage", async () => {
  const f = fixture(), elements = new Map(), destinations = [];
  const root = { body: { removeAttribute() {}, setAttribute() {} }, addEventListener() {}, querySelector(selector) {
    if (!elements.has(selector)) elements.set(selector, { listeners: {}, setAttribute() {}, removeAttribute() {},
      addEventListener(name, fn) { this.listeners[name] = fn; } });
    return elements.get(selector);
  } };
  const browser = { location: { hash: "", assign: (value) => destinations.push(value) }, addEventListener() {} };
  const binding = bindAuthenticatedEntry(root, { fetchImpl: f.fetchImpl, browser,
    privateLabelStore: { read() { assert.fail("unexpected storage"); }, write() { assert.fail("unexpected storage"); } },
    signerConnector() { assert.fail("unexpected signer"); } });
  await binding.ready;
  let prevented = false;
  elements.get("#sign-in").listeners.click({ preventDefault() { prevented = true; } });
  for (let n = 0; n < 20 && destinations.length === 0; n++) await new Promise((r) => setImmediate(r));
  assert.equal(prevented, true); assert.deepEqual(destinations, ["/auth/login"]);
  assert.equal((await f.send(destinations[0])).status, 302);
  assert.equal(f.sessions.size, 0);
});
