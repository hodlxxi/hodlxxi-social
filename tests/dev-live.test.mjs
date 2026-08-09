import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { DEV_LIVE_LIMITS, loadDevLiveSocial } from "../src/dev/live-social-composition.mjs";
import { NOTE_CONTENT_LIMIT, bindDevLivePage, renderAcceptedNotes } from "../web/dev-live.mjs";

const ada = "a".repeat(64);
const signed = (overrides = {}) => ({
  id: "e".repeat(64), pubkey: ada, created_at: 1, kind: 1, tags: [], content: "hello",
  sig: "f".repeat(128), ...overrides
});

class FakeWebSocket {
  constructor(url) { this.url = url; this.readyState = 0; this.sent = []; this.listeners = new Map(); }
  addEventListener(type, listener) { const set = this.listeners.get(type) ?? new Set(); set.add(listener); this.listeners.set(type, set); }
  removeEventListener(type, listener) { this.listeners.get(type)?.delete(listener); }
  send(value) { this.sent.push(value); }
  close() { this.readyState = 3; }
  emit(type, event = {}) { if (type === "open") this.readyState = 1; for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event); }
}

class Element {
  constructor(name = "div") { this.name = name; this.children = []; this.listeners = new Map(); this.textContent = ""; this.value = ""; this.disabled = false; }
  append(child) { this.children.push(child); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  querySelector(selector) { return selector === 'button[type="submit"]' ? this.button : undefined; }
}

function fakeDocument() {
  const elements = Object.fromEntries(["#dev-live-form", "#relay-url", "#event-limit", "#dev-live-status", "#dev-live-relay", "#dev-live-feed"].map((id) => [id, new Element()]));
  elements["#dev-live-form"].button = new Element("button");
  elements["#event-limit"].value = "3";
  return {
    elements,
    createElement: (name) => new Element(name),
    querySelector: (selector) => elements[selector]
  };
}

test("normal entry remains synthetic and dev-live is an explicit isolated entrypoint", async () => {
  const [index, app, devHtml] = await Promise.all([
    readFile(new URL("../web/index.html", import.meta.url), "utf8"),
    readFile(new URL("../web/app.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.html", import.meta.url), "utf8")
  ]);
  assert.match(index, /src="\.\/app\.mjs"/);
  assert.match(app, /new SyntheticSocialAdapter/);
  assert.doesNotMatch(index + app, /dev-live|WebSocketNostrReadTransport|NostrPublicReadAdapter/);
  assert.match(devHtml, /DEV \/ LIVE PUBLIC NOSTR DATA/);
  assert.match(devHtml, /DEMO VIEWER \/ AUTHORITY NOT LIVE/);
  assert.match(devHtml, /src="\.\/dev-live\.mjs"/);
  assert.doesNotMatch(devHtml, /value="wss:|relay\.damus\.io|nos\.lol|password|private.?key|nsec/i);
});

test("invalid relay and event bounds fail before WebSocket construction", async () => {
  let sockets = 0;
  const dependencies = { webSocketFactory: () => { sockets += 1; return new FakeWebSocket(); } };
  await assert.rejects(loadDevLiveSocial({ relayUrl: "https://relay.test" }, dependencies), /must use wss/);
  for (const limit of [0, 11, 1.5, "nope"]) await assert.rejects(loadDevLiveSocial({ relayUrl: "wss://relay.test", limit }, dependencies), /event limit/);
  assert.equal(sockets, 0);
  assert.deepEqual(DEV_LIVE_LIMITS, { defaultEvents: 3, maxEvents: 10, timeoutMs: 5000 });
});

test("one bounded transport read crosses adapter, composition, and service with authority closed", async () => {
  const sockets = [];
  const pending = loadDevLiveSocial({ relayUrl: "wss://relay.test" }, {
    webSocketFactory(url) { const socket = new FakeWebSocket(url); sockets.push(socket); return socket; }
  });
  assert.equal(sockets.length, 1);
  sockets[0].emit("open");
  const request = JSON.parse(sockets[0].sent[0]);
  assert.deepEqual(request[0], "REQ");
  assert.deepEqual(request[2], { kinds: [0, 1] });
  sockets[0].emit("message", { data: JSON.stringify(["EVENT", request[1], signed({ tags: [["unknown", "not rendered"]], content: "<img src=x onerror=alert(1)>" })]) });
  sockets[0].emit("message", { data: JSON.stringify(["EOSE", request[1]]) });
  const result = await pending;
  assert.equal(result.relayUrl, "wss://relay.test/");
  assert.equal(result.limit, 3);
  assert.equal(result.data.notes.length, 1);
  assert.equal(result.data.statuses[ada], AccessStatus.LIMITED);
  assert.equal(result.data.externalAssertions[ada].valid, false);
  assert.deepEqual(result.data.sponsorTrustEdges, []);
  assert.deepEqual(Object.keys(result.data.notes[0]).sort(), ["audience", "authorId", "body", "comments", "id", "reactions", "replies", "reposts", "timestamp"].sort());
});

test("safe renderer emits only normalized bounded text fields", () => {
  const document = fakeDocument();
  const feed = document.elements["#dev-live-feed"];
  const body = `<script>alert(1)</script>${"x".repeat(600)}`;
  renderAcceptedNotes(document, feed, {
    participants: [{ id: ada, publicKey: ada, displayName: "Ignored" }],
    notes: [{ authorId: ada, timestamp: "1970-01-01T00:00:01.000Z", body }]
  });
  assert.equal(feed.children.length, 1);
  assert.deepEqual(feed.children[0].children.map(({ name }) => name), ["strong", "time", "p"]);
  assert.equal(feed.children[0].children[2].textContent, body.slice(0, NOTE_CONTENT_LIMIT));
  assert.equal(feed.children[0].children.some(({ textContent }) => /Ignored|unknown|sig|tags/.test(textContent)), false);
});

test("manual submissions are one-shot, explicit for zero events, and clear failures", async () => {
  const document = fakeDocument();
  const calls = [];
  const binding = bindDevLivePage(document, { readLive: async (options) => {
    calls.push(options);
    return { relayUrl: "wss://relay.test/", data: { participants: [], notes: [] } };
  } });
  document.elements["#relay-url"].value = "wss://relay.test";
  const submit = binding.form.listeners.get("submit");
  await submit({ preventDefault() {} });
  assert.deepEqual(calls, [{ relayUrl: "wss://relay.test", limit: "3" }]);
  assert.match(document.elements["#dev-live-status"].textContent, /zero accepted/);
  assert.equal(document.elements["#dev-live-relay"].textContent, "wss://relay.test/");

  const failed = fakeDocument();
  failed.elements["#relay-url"].value = "invalid";
  const failureBinding = bindDevLivePage(failed, { readLive: async () => { throw new TypeError("relay URL is malformed"); } });
  await failureBinding.form.listeners.get("submit")({ preventDefault() {} });
  assert.match(failed.elements["#dev-live-status"].textContent, /Invalid relay.*No synthetic fallback/);
  assert.deepEqual(failed.elements["#dev-live-feed"].children, []);
});

test("dev-live code has no persistence, polling, reconnect, authority, secrets, or write path", async () => {
  const sources = await Promise.all([
    readFile(new URL("../src/dev/live-social-composition.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.html", import.meta.url), "utf8")
  ]);
  const source = sources.join("\n");
  assert.match(source, /WebSocketNostrReadTransport/);
  assert.match(source, /NostrPublicReadAdapter/);
  assert.match(source, /createComposedSocialDataService/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|document\.cookie|process\.env|location\.hostname|setInterval|setTimeout|reconnect|HodlxxiAuthorityReadAdapter|readAssertion|hodlxxi\.com|nsec|seed|NIP-07|NIP-44|NIP-59|\.publish\(|\bsign\w*\(|type=["']password/i);
});
