import assert from "node:assert/strict";
import test from "node:test";
import { createSessionStore } from "../src/server/social-oauth-memory.mjs";
import { createNativeV2SessionManager, createNativeV2SessionStore } from "../src/server/social-native-session-v2.mjs";

const at = 1700000000000, hex = (c) => c.repeat(64), denied = { message: "native v2 session unavailable" };
const delivery = () => ({ receipt: { schema: "hodlxxi.social_session_issuance.v2", version: 2,
  issuanceId: hex("a"), socialSessionIssuanceRevision: hex("b"), acceptanceId: hex("c"), issuedAt: at, expiresAt: at + 60000 },
  subject: hex("d"), currentActive: true, viewerAccessToken: "native.original.credential" });
function setup() {
  const state = { now: at, fail: false, resolveHook: null }, calls = [];
  const store = createNativeV2SessionStore({ ttlSeconds: 300, capacity: 4, now: () => state.now });
  const client = { resolve: async (args) => {
    calls.push(["resolve", args]); if (state.resolveHook) await state.resolveHook();
    if (state.fail) throw Error("private failure");
    const { viewerAccessToken, ...value } = delivery(); return value;
  }, revoke: async (args) => {
    calls.push(["revoke", args]); if (state.fail) throw Error("private failure");
    return { schema: "hodlxxi.social_session_revocation.v2", version: 2, issuanceId: hex("a"), status: "revoked" };
  } };
  let count = 0;
  const manager = createNativeV2SessionManager({ enabled: true, client, store, capacity: 4,
    now: () => state.now, random: (n) => Buffer.alloc(n, ++count) });
  const expectations = { subject: hex("d"), acceptanceId: hex("c"), maximumExpiresAt: at + 60000, stillCurrent: () => true };
  return { manager, store, client, calls, state, expectations };
}
test("native manager is default off without key, clock or transport access", () => {
  assert.equal(createNativeV2SessionManager(), undefined);
  assert.equal(createNativeV2SessionManager({ enabled: false, get client() { throw Error("must-not-read"); } }), undefined);
});
test("ordinary session store still rejects V2 while explicit store accepts its closed provenance", () => {
  const s = setup(), d = delivery();
  const record = { kind: "ubid-mobile-v2", subject: d.subject, viewerAccessToken: d.viewerAccessToken,
    issuanceId: d.receipt.issuanceId, issuanceRevision: d.receipt.socialSessionIssuanceRevision,
    acceptanceId: d.receipt.acceptanceId, issuedAt: d.receipt.issuedAt, expiresAt: d.receipt.expiresAt };
  assert.throws(() => createSessionStore({ ttlSeconds: 300, capacity: 4, now: () => at }).create("id", record));
  assert.equal(s.store.create("id", record), true);
  assert.throws(() => s.store.create("extra", { ...record, profile: "chosen" }));
});
test("accessor session fields are denied without invoking them", () => {
  const s = setup(); let invoked = false;
  assert.throws(() => s.store.create("id", { get kind() { invoked = true; return "ubid-mobile-v2"; } }));
  assert.equal(invoked, false);
});
test("install resolves native authority freshly and returns no private bearer", async () => {
  const s = setup(), result = await s.manager.install(delivery(), s.expectations);
  assert.equal(result.maxAge, 60); assert.equal(result.subject, hex("d"));
  assert.equal(JSON.stringify(result).includes("native.original.credential"), false);
  assert.equal((await s.manager.read(result.id)).receipt.expiresAt, at + 60000);
  assert.equal((await s.manager.capabilityRead(result.id)).kind, "ubid-mobile-v2");
  assert.equal(s.calls.length, 3);
});
test("concurrent exact retry keeps one original opaque presentation and never renews TTL", async () => {
  const s = setup();
  const [a, b] = await Promise.all([s.manager.install(delivery(), s.expectations), s.manager.install(delivery(), s.expectations)]);
  assert.equal(a.id, b.id); assert.equal(s.store.size, 1);
  s.state.now += 1000; const retry = await s.manager.install(delivery(), s.expectations);
  assert.equal(retry.id, a.id); assert.equal(retry.maxAge, 59);
});
test("V1 and altered revision never enter native manager", async () => {
  const s = setup();
  await assert.rejects(s.manager.install({ ...delivery(), receipt: { ...delivery().receipt, version: 1 } }, s.expectations), denied);
  await assert.rejects(s.manager.install({ ...delivery(), receipt: { ...delivery().receipt, socialSessionIssuanceRevision: hex("e") } }, s.expectations), denied);
  assert.equal(s.store.size, 0);
});
test("wrong original subject, acceptance or deadline denies without a local session", async () => {
  const s = setup();
  for (const change of [{ subject: hex("e") }, { acceptanceId: hex("e") }, { maximumExpiresAt: at + 59000 }])
    await assert.rejects(s.manager.install(delivery(), { ...s.expectations, ...change }), denied);
  assert.equal(s.store.size, 0);
});
test("cancellation during asynchronous resolve prevents cookie publication", async () => {
  const s = setup(); let current = true;
  s.state.resolveHook = () => { current = false; };
  await assert.rejects(s.manager.install(delivery(), { ...s.expectations, stillCurrent: () => current }), denied);
  assert.equal(s.store.size, 0);
});
test("expiry during asynchronous resolve prevents installation", async () => {
  const s = setup(); s.state.resolveHook = () => { s.state.now = at + 60000; };
  await assert.rejects(s.manager.install(delivery(), s.expectations), denied); assert.equal(s.store.size, 0);
});
test("failed logout immediately denies local reads; exact retry cancels original bearer", async () => {
  const s = setup(), installed = await s.manager.install(delivery(), s.expectations); s.state.fail = true;
  const failing = s.manager.logout(installed.id);
  assert.equal(s.store.get(installed.id), null); await assert.rejects(failing, denied);
  assert.equal(await s.manager.read(installed.id), null); s.state.fail = false;
  assert.equal(await s.manager.logout(installed.id), true);
  assert.equal(await s.manager.logout(installed.id), true);
  const attempts = s.calls.filter(([name]) => name === "revoke");
  assert.equal(attempts.length, 2); assert.deepEqual(attempts[0][1], attempts[1][1]);
});
test("expired session is retained only for bounded exact cancellation", async () => {
  const s = setup(), installed = await s.manager.install(delivery(), s.expectations);
  s.state.now = at + 60000; assert.equal(await s.manager.read(installed.id), null);
  assert.equal(await s.manager.logout(installed.id), true);
  s.state.now += 300000; await assert.rejects(s.manager.logout(installed.id), denied);
});
test("expired uninstalled original can be cancelled without session creation", async () => {
  const s = setup(); s.state.now = at + 90000;
  assert.equal(await s.manager.cancelUninstalled(delivery()), true); assert.equal(s.store.size, 0);
  assert.equal(s.calls[0][0], "revoke");
});
test("unavailable native owner denies each use of a retained presentation", async () => {
  const s = setup(), installed = await s.manager.install(delivery(), s.expectations); s.state.fail = true;
  assert.equal(await s.manager.read(installed.id), null); assert.equal(await s.manager.capabilityRead(installed.id), null);
});
