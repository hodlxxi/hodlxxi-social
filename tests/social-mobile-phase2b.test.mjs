import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createSessionStore, createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { createMobileSessionManager } from "../src/server/social-mobile-session-v1.mjs";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs";
import { createSocialMobileComposition } from "../src/server/social-mobile-composition-v1.mjs";
import { createUbidMobileAuthorizationClient, createUbidSessionIssuanceClient } from "../src/server/ubid-social-mobile-client-v1.mjs";
import { createMobileBrowserApi, createPhoneMobileController } from "../web/social-mobile-browser-v1.mjs";
import { canonical, parseClosedJson, validateReceipt, validateMobileResponse, validateIssuanceResponse, PROOF_FIELDS, VIEWER_HEADER, MOBILE_COMMANDS, validateCommand, inspectPhoneSource } from "../web/social-mobile-protocol-v1.mjs";
import { mountSocialMobileAuthorization } from "../web/social-mobile-ui-v1.mjs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/social_session_issuance_v1.json", import.meta.url)));
const ingress = JSON.parse(readFileSync(new URL("./fixtures/social_mobile_authorization_ingress_v1.json", import.meta.url)));
const subject = "a".repeat(64), viewerAccessToken = "server.only.credential";
const receipt = fixture.receipt, issuedAt = Date.parse(receipt.issuedAt), expiresAt = Date.parse(receipt.expiresAt);
const value = { receipt, subject, viewerAccessToken, currentActive: true };
const config = { publicOrigin: "https://social.example", authorityOrigin: "https://identity.example", clientId: "social", callbackUri: "https://social.example/auth/callback", scope: "openid profile", transactionTtlSeconds: 300, sessionTtlSeconds: 3600 };
function setup() {
  let time = issuedAt, resolves = 0, active = true, revokeCount = 0, failRevoke = false, gate;
  const sessions = createSessionStore({ ttlSeconds: 3600, capacity: 10, now: () => time });
  const issuanceClient = {
    async resolve({ body, viewerAccessToken: credential }) { resolves++; assert.deepEqual(body, { issuanceId: receipt.issuanceId }); assert.equal(credential, viewerAccessToken);
      if (gate) await gate; if (!active) throw Error("revoked"); return { receipt, subject, currentActive: true }; },
    async revoke({ body, viewerAccessToken: credential }) { revokeCount++; assert.equal(credential, viewerAccessToken);
      if (failRevoke) throw Error("lost reply"); active = false; return { schema: "hodlxxi.social_session_revocation.v1", version: 1, ...body, status: "revoked" }; }
  };
  const manager = createMobileSessionManager({ sessions, issuanceClient, now: () => time, mobileClient: {} });
  const install = () => manager.install(value, { subject, expiresAt, stillCurrent: () => true });
  return { sessions, manager, issuanceClient, install, clock: (v) => { time = v; }, block: (v) => { gate = v; }, revoke: () => { active = false; },
    failRevoke: (v) => { failRevoke = v; }, counts: () => ({ resolves, revokeCount }), now: () => time };
}
const barrier = () => { let release; const promise = new Promise((r) => { release = r; }); return { promise, release }; };

test("frozen source mapping and fixture byte identities match pinned Social base", () => {
  assert.equal(fixture.socialBase, "3116db8f7f257b677782e2654340d61c49ac537b");
  for (const [path, hash] of Object.entries(fixture.sourceSha256)) assert.equal(createHash("sha256").update(execFileSync("git", ["show", fixture.socialBase + ":" + path])).digest("hex"), hash);
  assert.deepEqual(PROOF_FIELDS, fixture.proofFields); assert.equal(VIEWER_HEADER, fixture.viewerHeader);
  assert.equal(createHash("sha256").update(readFileSync(new URL("./fixtures/social_mobile_device_authorization_v1.json", import.meta.url))).digest("hex"), ingress.phase1FixtureSha256);
  for (const [key, method] of [["acceptance", "qrAccept"], ["offer", "qrOffer"], ["legacyReservation", "legacyReserve"], ["handoffCreated", "phoneExchange"], ["handoffRecovered", "phoneExchange"]])
    assert.equal(canonical(validateMobileResponse(method, parseClosedJson(ingress[key]))), ingress[key]);
});

for (const bad of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"__proto__":{}}', '{"a":[[[[[1]]]]]}', '{"a":"\\u00e9"}', '{"a":NaN}', ' '.repeat(65537)])
  test("closed JSON denies hostile encoding " + bad.slice(0, 30), () => assert.throws(() => parseClosedJson(bad, { canonicalOnly: false })));
for (const field of ["schema", "version", "issuanceId", "issuedAt", "expiresAt", "extra"])
  test("receipt substitution rejected: " + field, () => assert.throws(() => validateReceipt({ ...receipt, [field]: "bad" })));
test("injected accessors and inherited fields are rejected without invoking accessors", () => {
  const v = { ...value }; Object.defineProperty(v, "subject", { get() { assert.fail("getter called"); }, enumerable: true });
  assert.throws(() => validateIssuanceResponse("issue", v)); assert.throws(() => validateReceipt(Object.create(receipt)));
});
test("disabled clients and browser perform zero calls", async () => {
  const deps = { requestImpl() { assert.fail("network"); } };
  assert.equal(createUbidMobileAuthorizationClient({ enabled: false }, deps), undefined);
  assert.equal(createUbidSessionIssuanceClient({}, deps), undefined);
  await assert.rejects(createMobileBrowserApi({ fetchImpl() { assert.fail("fetch"); } }).connect());
});
for (const name of Object.keys(MOBILE_COMMANDS)) test("closed operation body rejects unsigned overrides: " + name, () => {
  assert.throws(() => validateCommand(MOBILE_COMMANDS[name], { subject, viewerAccessToken, method: "qr_desktop_v1" }));
});

test("real session presentation is absolute, current, opaque, and one per issuance under concurrency", async () => {
  const f = setup(); const results = await Promise.all(Array.from({ length: 6 }, () => f.install()));
  assert.equal(new Set(results.map((r) => r.id)).size, 1); assert.equal(f.sessions.size, 1);
  const r = f.sessions.get(results[0].id); assert.equal(r.issuedAt, issuedAt); assert.equal(r.expiresAt, expiresAt);
  assert.equal(await f.manager.read(results[0].id), r); assert.equal(await f.manager.read(results[0].id), r);
  assert.equal(f.counts().resolves, 8);
  assert.equal(r.full, undefined); assert.equal(r.operator, undefined); assert.equal(r.privateKey, undefined);
});
test("one complete remaining second allowed; fractional second denied without extending expiry", async () => {
  const f = setup(); f.clock(expiresAt - 1000); const r = await f.install(); assert.equal(r.maxAge, 1);
  f.clock(expiresAt - 999); await assert.rejects(f.install()); f.clock(expiresAt); assert.equal(await f.manager.read(r.id), null);
});
test("historical JSON / absent viewer / inactive issuance / subject substitution cannot install", async () => {
  const f = setup(); for (const response of [JSON.parse(ingress.handoffCreated), receipt, { ...value, viewerAccessToken: undefined }, { ...value, currentActive: false }, { ...value, subject: "b".repeat(64) }])
    await assert.rejects(f.manager.install(response, { subject, expiresAt, stillCurrent: () => true }));
  assert.equal(f.sessions.size, 0);
});
test("malformed mobile store values never fall into browser TTL branch", () => {
  const f = setup(); for (const input of [{ issuanceId: receipt.issuanceId, subject }, { kind: "browser", subject }, { ...value, kind: "ubid-mobile-v1" }])
    assert.throws(() => f.sessions.create("x", input)); assert.equal(f.sessions.size, 0);
});
test("revoke before use denies; loss of local cache cannot reconstruct from old cookie", async () => {
  const f = setup(), r = await f.install(); f.revoke(); assert.equal(await f.manager.read(r.id), null);
  const restarted = setup(); assert.equal(await restarted.manager.read(r.id), null);
  const recovered = await restarted.install(); assert.notEqual(recovered.id, r.id); assert.deepEqual(recovered.receipt, r.receipt);
});
test("delayed resolve after local logout is denied; pending exact logout retry retains original credential", async () => {
  const f = setup(), r = await f.install(), gate = barrier();
  f.block(gate.promise); const read = f.manager.read(r.id);
  f.failRevoke(true); await assert.rejects(f.manager.logout(r.id)); gate.release(); assert.equal(await read, null);
  assert.equal(await f.manager.read(r.id), null);
  f.failRevoke(false); assert.equal(await f.manager.logout(r.id), true); assert.equal(await f.manager.logout(r.id), true);
  assert.equal(f.counts().revokeCount, 2); assert.equal(f.sessions.get(r.id), null);
});
test("expired original mobile credential remains eligible for exact logout", async () => {
  const f = setup(), r = await f.install(); f.clock(expiresAt + 1); assert.equal(await f.manager.read(r.id), null);
  assert.equal(await f.manager.logout(r.id), true); assert.equal(f.counts().revokeCount, 1);
});
test("expiring an unconfirmed desktop logout retry never restores its longer-lived session", async () => {
  let time = issuedAt;
  const sessions = createSessionStore({ ttlSeconds: 3600, capacity: 10, now: () => time });
  sessions.create("desktop", { subject, viewerAccessToken });
  const manager = createMobileSessionManager({ sessions, issuanceClient: {}, mobileClient: { oauthInvalidate: async () => { throw Error("offline"); } }, now: () => time });
  await assert.rejects(manager.logout("desktop")); assert.equal(await manager.read("desktop"), null);
  time += 300001; assert.equal(await manager.read("desktop"), null); assert.equal(sessions.get("desktop"), null);
});
test("malformed or mismatched logout acknowledgement cannot report success or revoke a replacement", async () => {
  const f = setup(), r = await f.install();
  f.issuanceClient.revoke = async () => ({ schema: "hodlxxi.social_session_revocation.v1", version: 1, issuanceId: "c".repeat(64), status: "revoked" });
  await assert.rejects(f.manager.logout(r.id));
  assert.equal(await f.manager.read(r.id), null);
  f.sessions.delete(r.id); f.sessions.create("replacement", { subject: "b".repeat(64), viewerAccessToken: "different.browser.credential" });
  await assert.rejects(f.manager.logout(r.id)); assert.equal(f.sessions.get("replacement").subject, "b".repeat(64));
});
test("nested proxy result cannot spoof a confidential receipt", async () => {
  const f = setup();
  await assert.rejects(f.manager.install({ ...value, receipt: new Proxy(receipt, { get() { assert.fail("proxy read"); } }) }, { subject, expiresAt, stillCurrent: () => true }));
  assert.equal(f.sessions.size, 0);
});
test("delayed current resolution cannot authenticate a replaced local object", async () => {
  const f = setup(), r = await f.install(), gate = barrier(); f.block(gate.promise);
  const read = f.manager.read(r.id);
  f.sessions.delete(r.id); f.sessions.create(r.id, { subject: "b".repeat(64), viewerAccessToken: "replacement.browser.credential" });
  gate.release(); assert.equal(await read, null);
});
test("late preinstallation response denied by context fence and by current resolve", async () => {
  const f = setup(); await assert.rejects(f.manager.install(value, { subject, expiresAt, stillCurrent: () => false }));
  f.revoke(); await assert.rejects(f.install()); assert.equal(f.sessions.size, 0);
});

const authenticatedPaths = ["/auth/session", "/auth/authority", "/auth/social-read-config", "/auth/social-publish-config", "/auth/messaging-device-binding-authorization-config", "/auth/full-directory",
  "/auth/recipient-capability", "/auth/messaging-recipient-package", "/auth/messaging-device-binding-authorization-intents", "/auth/messaging-device-binding-authorizations", "/auth/messaging-device-bindings"];
for (const path of authenticatedPaths) test("current resolution on every actual authenticated route: " + path, async () => {
  const f = setup(), r = await f.install();
  const bff = createSocialOAuthBff({ config, sessions: f.sessions, pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10 }), oauthClient: {}, sessionReader: f.manager.read });
  const method = ["/auth/recipient-capability", "/auth/messaging-recipient-package", "/auth/messaging-device-binding-authorization-intents", "/auth/messaging-device-binding-authorizations"].includes(path) ? "POST" : "GET";
  const request = { method, url: path, headers: { cookie: "__Host-hodlxxi-social-session=" + r.id, origin: config.publicOrigin } };
  await bff(request); assert.equal(f.counts().resolves, 2);
  f.revoke(); const denied = await bff(request); assert.equal(f.counts().resolves, 3);
  assert.equal(denied.status, path === "/auth/session" ? 200 : 401);
  assert.doesNotMatch(denied.body, new RegExp(viewerAccessToken));
});
test("BFF mobile identity never upgrades independent Limited/Full/operator context", async () => {
  const f = setup(), r = await f.install(); let status = "limited";
  const bff = createSocialOAuthBff({ config, sessions: f.sessions, pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10 }), oauthClient: {}, sessionReader: f.manager.read,
    authorityReader: async () => ({ subject, status, valid: true }) });
  const request = (url) => bff({ method: "GET", url, headers: { cookie: "__Host-hodlxxi-social-session=" + r.id } });
  for (status of ["limited", "full", "operator"]) {
    const result = JSON.parse((await request("/auth/authority")).body);
    assert.equal(result.subject, subject); assert.equal(result.status, status === "full" ? "full" : "limited");
  }
  f.revoke(); assert.deepEqual(JSON.parse((await request("/auth/session")).body), { authenticated: false });
});
test("all authentication helpers and every callsite await current resolution, including direct session route", () => {
  const source = readFileSync(new URL("../src/server/social-oauth-bff.mjs", import.meta.url), "utf8");
  for (const line of source.split("\n").filter((l) => /authenticated(SessionContext|Session|Subject)\(cookieHeader\)/.test(l))) assert.match(line, /await/);
  assert.doesNotMatch(source.slice(source.indexOf('target.path === "/auth/session"')), /id \? sessions.get\(id\)/);
});

test("reload with a preexisting pending non-extractable key never silently overwrites or resumes lost proofs", async () => {
  const keys = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const record = structuredClone({ subject, privateKey: keys.privateKey }); let writes = 0;
  const phone = createPhoneMobileController({ enabled: true, api: { qrOffer: async () => JSON.parse(ingress.offer) }, store: { read: async () => record, create: async () => writes++ }, cryptoImpl: webcrypto, CryptoKeyImpl: webcrypto.CryptoKey });
  await assert.rejects(phone.scan("hodlxxi-social-pair:v1:" + "9".repeat(64) + ":" + "8".repeat(64)));
  assert.equal(writes, 0); assert.equal(record.privateKey.extractable, false);
  assert.equal(phone.state().recovery, "proofs-unavailable-new-login-required");
  await assert.rejects(webcrypto.subtle.exportKey("jwk", record.privateKey));
});
test("interrupted browser scan retains exact key/proposal/proofs; terminal cleanup requires irreversible authoritative state", async () => {
  const offer = JSON.parse(ingress.offer); let device, saved = 0, deletes = 0, state = "awaiting-approval", parsed, firstSource, scans = 0, issues = 0;
  const store = { read: async () => device && structuredClone(device), create: async (v) => { assert.equal(device, undefined); saved++; device = structuredClone(v); },
    discardCancelledPending: async (expected) => { assert.equal(expected.publicKey, device.publicKey); assert.equal(expected.requestId, device.requestId); deletes++; device = undefined; } };
  const api = { qrOffer: async () => offer,
    qrScan: async ({ source }) => { parsed = await inspectPhoneSource(source, webcrypto); scans++; if (!firstSource) firstSource = source; assert.equal(source, firstSource);
      if (scans === 1) throw Error("interrupted after key persistence"); return { source, revision: offer.revision, status: state }; },
    phoneStatus: async () => ({ status: state, authorizationDigest: parsed.digest }),
    phoneRecover: async ({ source }) => { assert.equal(source, firstSource); return { status: state, authorizationDigest: parsed.digest }; },
    issue: async () => { issues++; throw Error("not admitted"); } };
  const phone = createPhoneMobileController({ enabled: true, api, store, cryptoImpl: webcrypto, CryptoKeyImpl: webcrypto.CryptoKey, now: () => Date.parse(offer.createdAt) });
  const qr = "hodlxxi-social-pair:v1:" + offer.pairingId + ":" + "8".repeat(64);
  await assert.rejects(phone.scan(qr)); const originalKey = device.publicKey;
  await phone.scan(qr); assert.equal(saved, 1); assert.equal(device.publicKey, originalKey); assert.equal(device.privateKey.extractable, false);
  for (state of ["awaiting-approval", "approval-claimed", "never-accepted", "expired", "abandoned", "rejected"]) {
    await assert.rejects(phone.complete()); assert.equal(issues, 0);
    if (state !== "rejected") await assert.rejects(phone.cleanupCancelled());
  }
  assert.equal(deletes, 0); state = "cancelled"; await phone.cleanupCancelled(); assert.equal(deletes, 1);
  assert.equal(phone.state().pending, false);
});
test("minimal UI is explicitly injected; mounting/polling never acquires NIP-07", async () => {
  let fetches = 0, providers = 0;
  assert.equal(await mountSocialMobileAuthorization({ resolveProvider: () => providers++ }), undefined);
  const element = () => ({ children: [], textContent: "", setAttribute() {}, addEventListener(name, fn) { this[name] = fn; } });
  const root = { ownerDocument: { createElement: element }, children: [], replaceChildren(...v) { this.children = v; }, append(v) { this.children.push(v); } };
  await mountSocialMobileAuthorization({ enabled: true, root, role: "desktop", subject,
    fetchImpl: async (path) => { fetches++; assert.equal(path, "/auth/mobile/v1/context"); return { status: 200, text: async () => canonical({ csrf: "c".repeat(64) }) }; }, resolveProvider: () => providers++ });
  assert.equal(fetches, 1); assert.equal(providers, 0);
  assert.match(root.children[0].textContent, /original pairing deadline/);
  assert.ok(root.children.some((v) => v.textContent === "Approve matching code"));
  assert.ok(root.children.some((v) => v.textContent === "Retry saved approval"));
});
