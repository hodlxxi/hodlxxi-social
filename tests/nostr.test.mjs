import test from "node:test";
import assert from "node:assert/strict";
import { createNostrBoundary, mapNoteEvent, mapProfileEvent, validatePublicEvent, validatePublicRelayFilter } from "../src/nostr.mjs";

const pubkey = "a".repeat(64);
const signed = (event) => ({ id: "e".repeat(64), pubkey, created_at: 1, tags: [], sig: "f".repeat(128), ...event });
test("public Nostr events map to domain records", () => {
  assert.equal(mapProfileEvent(signed({kind:0,content:'{"display_name":"Synthetic"}'})).displayName, "Synthetic");
  assert.equal(mapNoteEvent(signed({kind:1,created_at:2,content:"hello"})).authorId, pubkey);
});
test("mappers reject incomplete or private-key-bearing events", () => {
  assert.throws(() => mapNoteEvent({kind:1,pubkey,created_at:2,tags:[],content:"hello"}));
  assert.throws(() => mapProfileEvent(signed({kind:0,content:"{}",privateKey:"secret"})));
  assert.throws(() => mapNoteEvent(signed({kind:1,content:"hello",nsec:"secret"})));
});
test("relay behavior is replaceable and injected", async () => {
  const calls = [];
  const boundary = createNostrBoundary({read: async (filter) => { calls.push(["read",filter]); return []; }, publish: async (event) => { calls.push(["publish",event]); return "accepted"; }});
  const event = {kind:1,pubkey,created_at:2,tags:[],content:"hello"};
  await boundary.read({kinds:[1]}); await boundary.publish(event);
  assert.deepEqual(calls, [["read",{kinds:[1]}],["publish",event]]);
  assert.throws(() => createNostrBoundary({}));
});
test("valid relay filters are normalized, copied, and frozen before read", async () => {
  const calls = [];
  const input = { ids: ["AB12"], authors: ["CD34"], kinds: [0, 1], since: 0, until: 10, limit: 500, "#e": ["EF56"], "#p": ["A0"] };
  const snapshot = structuredClone(input);
  const boundary = createNostrBoundary({ read: async (filter) => { calls.push(filter); return "read"; }, publish: async () => "accepted" });

  assert.equal(await boundary.read(input), "read");
  assert.deepEqual(input, snapshot);
  assert.deepEqual(calls[0], { ids: ["ab12"], authors: ["cd34"], kinds: [0, 1], since: 0, until: 10, limit: 500, "#e": ["ef56"], "#p": ["a0"] });
  assert.notEqual(calls[0], input);
  assert.notEqual(calls[0].authors, input.authors);
  assert.equal(Object.isFrozen(calls[0]), true);
  for (const field of ["ids", "authors", "kinds", "#e", "#p"]) assert.equal(Object.isFrozen(calls[0][field]), true);
  assert.throws(() => calls[0].authors.push("ff"), TypeError);
});
test("a kinds-only V0 relay filter succeeds", () => {
  assert.deepEqual(validatePublicRelayFilter({ kinds: [1] }), { kinds: [1] });
});
test("private and unknown relay filter fields fail before adapter read", () => {
  let reads = 0;
  const boundary = createNostrBoundary({ read: () => { reads += 1; return []; }, publish: async () => "accepted" });
  for (const filter of [
    { privateKey: "secret" },
    { private_key: "secret" },
    { nsec: "secret" },
    { secret: "secret" },
    { search: "unsupported" }
  ]) assert.throws(() => boundary.read(filter), TypeError);
  assert.equal(reads, 0);
});
test("relay filters must be plain objects", () => {
  for (const filter of [null, [], "kinds", 1, new Date()]) assert.throws(() => validatePublicRelayFilter(filter), TypeError);
});
test("relay filter identifiers and authors reject malformed prefixes", () => {
  const sparseIds = [];
  sparseIds.length = 1;
  for (const filter of [
    { ids: "aa" },
    { ids: [""] },
    { ids: ["not-hex"] },
    { ids: ["a".repeat(65)] },
    { ids: sparseIds },
    { authors: [1] },
    { authors: ["0x12"] },
    { authors: ["b".repeat(65)] },
    { "#e": [""] },
    { "#p": ["xyz"] }
  ]) assert.throws(() => validatePublicRelayFilter(filter), TypeError);
});
test("relay filter kinds, timestamps, and limits fail closed", () => {
  for (const filter of [
    { kinds: [-1] },
    { kinds: [1.5] },
    { kinds: ["1"] },
    { since: -1 },
    { since: 1.5 },
    { until: -1 },
    { until: Number.MAX_SAFE_INTEGER + 1 },
    { limit: 0 },
    { limit: 1.5 },
    { limit: 501 }
  ]) assert.throws(() => validatePublicRelayFilter(filter), TypeError);
});
test("publish rejects malformed and private-key-bearing input", async () => {
  const event = {kind:1,pubkey,created_at:2,tags:[],content:"hello"};
  assert.equal(validatePublicEvent(event).pubkey, pubkey);
  assert.throws(() => validatePublicEvent({...event, privateKey:"secret"}));
  assert.throws(() => validatePublicEvent({...event, tags:[42]}));
  const boundary = createNostrBoundary({read:async()=>[],publish:async()=>"unexpected"});
  await assert.rejects(async () => boundary.publish({...event, nsec:"secret"}));
});
