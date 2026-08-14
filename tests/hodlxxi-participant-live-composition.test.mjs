import test from "node:test";
import assert from "node:assert/strict";
import { NostrPublicReadAdapter } from "../src/data/nostr-public-read-adapter.mjs";
import { createComposedSocialDataService } from "../src/data/composition.mjs";
import { loadParticipantLive, parseParticipantLiveOptions } from "../src/dev/hodlxxi-participant-live-composition.mjs";

const subject = "a".repeat(64);
const input = { origin: "https://authority.example", relayUrl: "wss://relay.example/", subject, timeoutMs: 5000, noteLimit: 3 };
const authority = Object.freeze({ assertedIdentityClass: "full" });

function dependencies({ authorityFailure = false, nostrFailureKind } = {}) {
  const filters = [];
  let authorityCalls = 0;
  const transportFactory = ({ relayUrl }) => ({
    relayUrl: new URL(relayUrl).href,
    read: async (filter) => { filters.push(filter); if (filter.kinds[0] === nostrFailureKind) throw new Error("private transport detail"); return filter; }
  });
  const adapterFactory = async ({ transport, viewerId }) => ({ viewerId, filter: await transport.read() });
  const compose = ({ socialAdapter }) => ({ load: () => socialAdapter.filter.kinds[0] === 0
    ? { participants: [{ id: subject, publicKey: subject, displayName: "Ada" }], notes: [] }
    : { participants: [{ id: subject }], notes: [{ id: "1", authorId: subject, body: "hello", timestamp: "2026-08-14T00:00:00.000Z" }] } });
  return {
    values: { filters, get authorityCalls() { return authorityCalls; } },
    deps: { transportFactory, adapterFactory, compose, authorityFormat: () => {}, authorityCompose: async (options) => { authorityCalls += 1; assert.equal(options.subject, subject); if (authorityFailure) throw new Error("secret authority body"); return authority; } }
  };
}

test("validation is idle and rejects every invalid input before reads", () => {
  let constructions = 0;
  const transportFactory = ({ relayUrl }) => { constructions += 1; return { relayUrl: new URL(relayUrl).href }; };
  assert.equal(constructions, 0);
  assert.throws(() => parseParticipantLiveOptions({ ...input, subject: subject.toUpperCase() }, { transportFactory }));
  assert.throws(() => parseParticipantLiveOptions({ ...input, origin: "http://authority.example" }, { transportFactory }));
  assert.throws(() => parseParticipantLiveOptions({ ...input, noteLimit: 11 }, { transportFactory }));
  for (const timeoutMs of [249, 30001]) assert.throws(() => parseParticipantLiveOptions({ ...input, timeoutMs }, { transportFactory }));
  assert.equal(constructions, 0);
  assert.throws(() => parseParticipantLiveOptions({ ...input, relayUrl: "ws://relay.example" }));
  assert.throws(() => parseParticipantLiveOptions({ ...input, relayUrl: "wss://user:secret@relay.example/" }));
  for (const relayUrl of ["wss://relay.example", "wss://RELAY.example/", "wss://relay.example:443/"]) {
    let reads = 0;
    const countingFactory = (factoryOptions) => {
      const canonical = new URL(factoryOptions.relayUrl).href;
      return { relayUrl: canonical, read: () => { reads += 1; } };
    };
    assert.throws(() => parseParticipantLiveOptions({ ...input, relayUrl }, { transportFactory: countingFactory }), /canonical/);
    assert.equal(reads, 0);
  }
});

test("one load uses the same subject in exact profile and bounded note filters", async () => {
  const { deps, values } = dependencies();
  const result = await loadParticipantLive(input, deps);
  assert.equal(values.authorityCalls, 1);
  assert.deepEqual(values.filters, [
    { authors: [subject], kinds: [0], limit: 1 },
    { authors: [subject], kinds: [1], limit: 3 }
  ]);
  assert.equal(result.subject, subject);
  assert.equal(result.relayUrl, input.relayUrl);
  assert.equal(result.authority.status, "fulfilled");
  assert.equal(result.profile.status, "fulfilled", result.profile.reason?.stack);
  assert.equal(result.notes.status, "fulfilled", result.notes.reason?.stack);
  assert.equal(result.profile.value.displayName, "Ada");
  assert.equal(result.notes.value[0].authorId, subject);
});

test("authority and Nostr failures settle independently", async () => {
  const authorityFailed = dependencies({ authorityFailure: true });
  const first = await loadParticipantLive(input, authorityFailed.deps);
  assert.equal(first.authority.status, "rejected");
  assert.equal(first.profile.status, "fulfilled");
  assert.equal(first.notes.status, "fulfilled");

  const notesFailed = dependencies({ nostrFailureKind: 1 });
  const second = await loadParticipantLive(input, notesFailed.deps);
  assert.equal(second.authority.status, "fulfilled");
  assert.equal(second.profile.status, "fulfilled");
  assert.equal(second.notes.status, "rejected");
});

test("missing profile and empty notes remain successful empty states", async () => {
  const { deps } = dependencies();
  deps.compose = ({ socialAdapter }) => ({ load: () => ({ participants: [], notes: [], filter: socialAdapter.filter }) });
  const result = await loadParticipantLive(input, deps);
  assert.equal(result.profile.status, "fulfilled");
  assert.equal(result.profile.value, null);
  assert.deepEqual(result.notes.value, []);
});

const signed = (overrides = {}) => ({ id: "e".repeat(64), pubkey: subject, created_at: 1, kind: 1, tags: [], content: "hello", sig: "f".repeat(128), ...overrides });

test("existing Nostr adapter and composition reject malformed and off-subject relay results", async () => {
  for (const eventsForKind of [
    () => [signed({ privateKey: "forbidden" })],
    (kind) => [signed({ pubkey: "b".repeat(64), kind, content: kind === 0 ? '{"name":"Mallory"}' : "wrong author" })]
  ]) {
    const transportFactory = ({ relayUrl }) => ({ relayUrl: new URL(relayUrl).href, read: (filter) => eventsForKind(filter.kinds[0]) });
    const result = await loadParticipantLive(input, {
      transportFactory,
      adapterFactory: NostrPublicReadAdapter.create,
      compose: createComposedSocialDataService,
      authorityCompose: async () => authority,
      authorityFormat: () => {}
    });
    assert.equal(result.profile.status, "rejected");
    assert.equal(result.notes.status, "rejected");
  }
});
