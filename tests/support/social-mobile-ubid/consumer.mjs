// Executed only by the guarded synthetic fixture; never imported by discovery.
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { createPrivateKey, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createUbidMobileAuthorizationClient, createUbidSessionIssuanceClient } from "../../../src/server/ubid-social-mobile-client-v1.mjs";
import { createSocialMobileComposition } from "../../../src/server/social-mobile-composition-v1.mjs";
import { createSessionStore, createBoundedStore } from "../../../src/server/social-oauth-memory.mjs";
import { createHttpHandler } from "../../../scripts/hodlxxi-social-server.mjs";
import { createMobileBrowserApi, createPhoneMobileController, createDesktopMobileController } from "../../../web/social-mobile-browser-v1.mjs";
import { canonical } from "../../../web/social-mobile-protocol-v1.mjs";
const input = JSON.parse(readFileSync(0, "utf8")), now = () => input.now;
const transport = { enabled: true, issuerOrigin: input.issuerOrigin, socketPath: process.env.SOCIAL_UBID_SOCKET, clientId: input.clientId,
  clientSigningKeyId: "client-test", signingKey: createPrivateKey(input.backendKey), timeoutMs: 5000 };
delete input.backendKey;
const realMobileClient = createUbidMobileAuthorizationClient(transport), realIssuanceClient = createUbidSessionIssuanceClient(transport);
let loseExchange = false, loseIssuance = false;
const mobileClient = Object.freeze({ ...realMobileClient, async phoneExchange(input) {
  const result = await realMobileClient.phoneExchange(input);
  if (loseExchange) { loseExchange = false; throw Error("synthetic lost committed exchange response"); } return result;
} });
const issuanceClient = Object.freeze({ ...realIssuanceClient, async issue(input) {
  const result = await realIssuanceClient.issue(input);
  if (loseIssuance) { loseIssuance = false; throw Error("synthetic lost committed issuance response"); } return result;
} });
const config = { publicOrigin: "https://social.example", authorityOrigin: input.issuerOrigin, clientId: "synthetic-social", callbackUri: "https://social.example/auth/callback", scope: "openid profile", transactionTtlSeconds: 300, sessionTtlSeconds: 3600 };
let composition, sessions;
function compose() {
  sessions = createSessionStore({ ttlSeconds: 3600, capacity: 100, now });
  composition = createSocialMobileComposition({ enabled: true, mobileClient, issuanceClient, sessions, config, now,
    pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10, now }), oauthClient: {},
    authorityReader: async (subject) => ({ subject, status: "limited", valid: true }) });
}
compose();
// Fixture admitted this exact viewer via real verified Nostr browser login and
// real /oauth/authorize + /oauth/token against the synthetic PostgreSQL ledger.
sessions.create("synthetic-desktop-cookie", { subject: input.subject, viewerAccessToken: input.viewerAccessToken });
const server = http.createServer((req, res) => createHttpHandler({ publicOrigin: config.publicOrigin, bff: composition.bff, mobilePostRoutes: composition.mobilePostRoutes })(req, res));
server.listen(process.env.SOCIAL_TEST_SOCKET); await once(server, "listening");
function request(socketPath, path, { method = "POST", body = "{}", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ socketPath, path, method, agent: false, headers: { Host: "social.example", "Content-Length": String(Buffer.byteLength(body)), ...headers } }, (response) => {
      const chunks = []; response.on("data", (c) => chunks.push(c)); response.once("error", reject);
      response.once("end", () => resolve({ status: response.statusCode, headers: response.headers, text: async () => Buffer.concat(chunks).toString("utf8") }));
    }); r.once("error", reject); r.setTimeout(5000, () => r.destroy(Error("synthetic request timeout"))); r.end(body);
  });
}
function browser(initial) {
  const jar = new Map(initial ? [["__Host-hodlxxi-social-session", initial]] : []); let drop;
  const fetchImpl = async (path, options) => {
    assert.doesNotMatch(options.body, /privateKey|viewerAccessToken|access_token|PRIVATE KEY/);
    const response = await request(process.env.SOCIAL_TEST_SOCKET, path, { ...options, headers: { ...options.headers, Origin: config.publicOrigin, Cookie: [...jar].map(([k, v]) => k + "=" + v).join("; ") } });
    if (drop === path && response.status === 200) { drop = undefined; throw Error("synthetic lost response"); }
    for (const cookie of response.headers["set-cookie"] ?? []) {
      const [name, value] = cookie.split(";")[0].split("="); if (value) jar.set(name, value); else jar.delete(name);
    }
    return response;
  };
  return { jar, fetchImpl, drop: (path) => { drop = path; }, clear: () => jar.clear(),
    async session() { const r = await request(process.env.SOCIAL_TEST_SOCKET, "/auth/session", { method: "GET", body: "", headers: { Cookie: [...jar].map(([k, v]) => k + "=" + v).join("; ") } }); return JSON.parse(await r.text()); } };
}
try {
  const desktopBrowser = browser("synthetic-desktop-cookie"), phoneBrowser = browser();
  const desktopApi = createMobileBrowserApi({ enabled: true, fetchImpl: desktopBrowser.fetchImpl });
  const phoneApi = createMobileBrowserApi({ enabled: true, fetchImpl: phoneBrowser.fetchImpl });
  await desktopApi.connect(); await phoneApi.connect();
  const retries = new Map(); let signCount = 0, providerCount = 0, device;
  const desktop = createDesktopMobileController({ enabled: true, api: desktopApi, subject: input.subject, cryptoImpl: webcrypto, now,
    retryStore: { save: async (id, s) => retries.set(id, s), read: async (id) => retries.get(id) },
    resolveProvider: () => { providerCount++; return { getPublicKey: async () => input.subject, signEvent: async (event) => {
      signCount++; const r = await request(process.env.SOCIAL_UBID_SOCKET, "/__synthetic/sign", { body: canonical(event) });
      assert.equal(r.status, 200); return JSON.parse(await r.text()); } }; } });
  const store = { read: async () => device && structuredClone(device), create: async (v) => { assert.equal(device, undefined); device = structuredClone(v); } };
  const phone = createPhoneMobileController({ enabled: true, api: phoneApi, store, cryptoImpl: webcrypto, CryptoKeyImpl: webcrypto.CryptoKey, now });
  const creation = await desktop.create(); console.log("REAL_OAUTH_ADMISSION_AND_QR_CREATE=PASS");
  const scanned = await phone.scan(creation.qr); assert.equal(scanned.status, "awaiting-approval");
  assert.equal((await phoneBrowser.session()).authenticated, false);
  await assert.rejects(phone.complete());
  const inspected = await desktop.inspect(); assert.equal(inspected.comparisonCode, scanned.comparisonCode); assert.equal(providerCount, 0);
  desktopBrowser.drop("/auth/mobile/v1/qr/accept");
  await assert.rejects(desktop.approve(scanned.comparisonCode));
  assert.equal((await desktop.inspect()).status, "accepted");
  await desktop.retryAcceptance(); assert.equal(signCount, 1); assert.equal(providerCount, 1);
  console.log("LOST_ACCEPTANCE_RESPONSE_WITHOUT_RESIGN=PASS");
  assert.equal((await phoneBrowser.session()).authenticated, false);
  loseExchange = true; await assert.rejects(phone.complete());
  assert.equal((await phoneBrowser.session()).authenticated, false);
  loseIssuance = true; await assert.rejects(phone.complete());
  assert.equal((await phoneBrowser.session()).authenticated, false);
  console.log("LOST_UBID_EXCHANGE_AND_ISSUANCE_RESPONSES=PASS");
  phoneBrowser.drop("/auth/mobile/v1/session/issue");
  await assert.rejects(phone.complete());
  const recovered = await phone.recover();
  assert.equal(recovered.authenticated, true); assert.equal(recovered.subject, input.subject);
  assert.equal((await phoneBrowser.session()).subject, input.subject);
  const firstAlias = phoneBrowser.jar.get("__Host-hodlxxi-social-session"), firstRecord = sessions.get(firstAlias);
  assert.equal(firstRecord.expiresAt, Date.parse(creation.offer.expiresAt));
  const equal = await phone.complete(); assert.deepEqual(equal, recovered);
  assert.equal(phoneBrowser.jar.get("__Host-hodlxxi-social-session"), firstAlias);
  console.log("LOST_SOCIAL_RESPONSE_SAME_PRESENTATION=PASS");
  compose(); assert.equal((await phoneBrowser.session()).authenticated, false);
  // Real controller bootstrap handles stale cookies after cache loss; no
  // manual cookie deletion or caller-supplied subject is needed for recovery.
  await phoneApi.connect();
  const restarted = await phone.recover(); assert.deepEqual(restarted, recovered);
  const newAlias = phoneBrowser.jar.get("__Host-hodlxxi-social-session"), newRecord = sessions.get(newAlias);
  assert.notEqual(newAlias, firstAlias); assert.equal(newRecord.viewerAccessToken, firstRecord.viewerAccessToken);
  assert.equal(newRecord.issuanceId, firstRecord.issuanceId); assert.equal(newRecord.expiresAt, firstRecord.expiresAt);
  assert.equal((await phoneBrowser.session()).subject, input.subject);
  console.log("RESTART_RECOVERS_SAME_TOKEN_RECEIPT_DEADLINE=PASS");
  // Enabled desktop logout invalidates the original real parent generation.
  sessions.create("synthetic-desktop-retry", { subject: input.subject, viewerAccessToken: input.viewerAccessToken });
  const oldDesktop = browser("synthetic-desktop-retry"), oldDesktopApi = createMobileBrowserApi({ enabled: true, fetchImpl: oldDesktop.fetchImpl });
  await oldDesktopApi.connect(); assert.equal((await oldDesktopApi.logout()).logout, "confirmed");
  assert.equal((await phoneBrowser.session()).authenticated, false);
  console.log("PARENT_INVALIDATION_DENIES_NEXT_MOBILE_USE=PASS");
  assert.equal(device.privateKey.extractable, false); await assert.rejects(webcrypto.subtle.exportKey("jwk", device.privateKey));
  const loggedOut = await phone.logout(); assert.equal(loggedOut.logout, "confirmed");
  assert.equal((await phoneBrowser.session()).authenticated, false);
  await assert.rejects(issuanceClient.resolve({ body: { issuanceId: newRecord.issuanceId }, viewerAccessToken: newRecord.viewerAccessToken }));
  assert.equal((await store.read()).privateKey.extractable, false);
  console.log("EXACT_REVOKE_AND_CURRENT_USE_DENIAL=PASS");
  console.log("EXPLICIT_NIP07_SIGN_EVENT_COUNT=" + signCount);
} finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
