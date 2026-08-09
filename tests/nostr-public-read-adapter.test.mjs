import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { SocialCapability } from "../src/data/capabilities.mjs";
import { NostrPublicReadAdapter } from "../src/data/nostr-public-read-adapter.mjs";
import { createSocialDataService } from "../src/data/service.mjs";

const ada = "a".repeat(64);
const ben = "b".repeat(64);
const signed = (overrides = {}) => ({
  id: "e".repeat(64), pubkey: ada, created_at: 1, kind: 1, tags: [], content: "hello", sig: "f".repeat(128), ...overrides
});

test("public adapter injects one constrained read and satisfies the Social service", async () => {
  const calls = [];
  const events = [
    signed({ id: "1".repeat(64), pubkey: ben, created_at: 4, content: "from fallback participant" }),
    signed({ id: "2".repeat(64), kind: 0, created_at: 3, content: JSON.stringify({ display_name: "Ada", status: "operator", extra: "discarded" }) }),
    signed({ id: "3".repeat(64), created_at: 5, content: "public note" })
  ];
  const adapter = await NostrPublicReadAdapter.create({
    viewerId: ada.toUpperCase(),
    transport: { read: async (filter) => { calls.push(filter); return events; } }
  });
  const data = createSocialDataService(adapter).load();

  assert.deepEqual(calls, [{ kinds: [0, 1] }]);
  assert.equal(Object.isFrozen(calls[0]), true);
  assert.equal(adapter.capabilities.includes(SocialCapability.READ_PUBLIC_NOSTR), true);
  assert.equal(data.currentViewerId, ada);
  assert.deepEqual(data.participants.map(({ id, displayName }) => [id, displayName]), [[ada, "Ada"], [ben, "Participant"]]);
  assert.deepEqual(data.notes.map(({ id, authorId, audience, body, timestamp, reactions, comments, reposts }) =>
    ({ id, authorId, audience, body, timestamp, reactions, comments, reposts })), [
    { id: "1".repeat(64), authorId: ben, audience: "PUBLIC", body: "from fallback participant", timestamp: "1970-01-01T00:00:04.000Z", reactions: 0, comments: 0, reposts: 0 },
    { id: "3".repeat(64), authorId: ada, audience: "PUBLIC", body: "public note", timestamp: "1970-01-01T00:00:05.000Z", reactions: 0, comments: 0, reposts: 0 }
  ]);
  assert.deepEqual(data.edges, []);
  assert.deepEqual(data.groups, []);
  assert.deepEqual(data.conversations, []);
  assert.deepEqual(data.notifications, []);
  assert.deepEqual(Object.values(data.statuses), [AccessStatus.LIMITED, AccessStatus.LIMITED]);
  assert.equal("status" in data.participants[0], false);
  assert.equal("tags" in data.notes[0], false);
  assert.equal("sig" in data.notes[0], false);
  assert.equal(Object.isFrozen(adapter), true);
  assert.equal(Object.isFrozen(data.notes), true);
});

test("event ordering and duplicate resolution are deterministic", async () => {
  const older = signed({ id: "4".repeat(64), kind: 0, created_at: 1, content: '{"name":"Older"}' });
  const newer = signed({ id: "5".repeat(64), kind: 0, created_at: 2, content: '{"name":"Newer"}' });
  const first = signed({ id: "6".repeat(64), created_at: 3, content: "a conflicting duplicate" });
  const last = signed({ id: "6".repeat(64), created_at: 3, content: "z conflicting duplicate" });
  const profileFirst = signed({ id: "7".repeat(64), kind: 0, created_at: 4, content: '{"name":"A conflict"}' });
  const profileLast = signed({ id: "7".repeat(64), kind: 0, created_at: 4, content: '{"name":"Z conflict"}' });
  const load = async (events) => NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: () => events } });

  const forward = await load([older, newer, first, last, profileFirst, profileLast]);
  const reverse = await load([profileLast, last, first, profileFirst, newer, older]);
  assert.deepEqual(forward.listParticipants(), reverse.listParticipants());
  assert.deepEqual(forward.listFeed(), reverse.listFeed());
  assert.equal(forward.listParticipants()[0].displayName, "Z conflict");
  assert.equal(forward.listFeed()[0].body, "z conflicting duplicate");
});

test("missing or failing transports fail closed", async () => {
  await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada }), TypeError);
  await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada, transport: {} }), TypeError);
  await assert.rejects(NostrPublicReadAdapter.create({ viewerId: "invalid", transport: { read: () => [] } }), TypeError);
  await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: () => { throw new Error("offline"); } } }), /offline/);
  await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: async () => { throw new Error("rejected"); } } }), /rejected/);
  for (const result of [null, {}, "events", 1]) {
    await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: () => result } }), TypeError);
  }
  assert.throws(() => new NostrPublicReadAdapter(), TypeError);
});

test("unsupported, malformed, unsigned, and private-bearing events fail closed", async () => {
  const cases = [
    signed({ kind: 3 }),
    signed({ kind: 4 }),
    signed({ kind: 99 }),
    { kind: 1, pubkey: ada, created_at: 1, tags: [], content: "unsigned" },
    signed({ tags: [42] }),
    signed({ privateKey: "not accepted" }),
    signed({ nsec: "not accepted" })
  ];
  for (const event of cases) {
    await assert.rejects(NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: () => [event] } }), TypeError);
  }
});

test("adapter source contains no live, secret, publish, signing, or authority path", async () => {
  const source = await readFile(new URL("../src/data/nostr-public-read-adapter.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /WebSocket|fetch\(|XMLHttpRequest|process\.env|localStorage|sessionStorage|indexedDB|private.?key|\.publish\(|\bsign\w*\(|grantFull|setOperator|approveTrust|issueCRT|bitcoin|lightning|custody/i);
  const adapter = await NostrPublicReadAdapter.create({ viewerId: ada, transport: { read: () => [] } });
  assert.equal(adapter.publish, undefined);
  assert.equal(adapter.sign, undefined);
});
