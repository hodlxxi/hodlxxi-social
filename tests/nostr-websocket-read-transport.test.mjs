import test from "node:test";
import assert from "node:assert/strict";
import { AccessStatus } from "../src/domain.mjs";
import { NostrPublicReadAdapter } from "../src/data/nostr-public-read-adapter.mjs";
import { WebSocketNostrReadTransport } from "../src/data/nostr-websocket-read-transport.mjs";
import { createSocialDataService } from "../src/data/service.mjs";

class FakeWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
    this.closeCalls = 0;
    this.listeners = new Map();
  }
  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }
  removeEventListener(type, listener) { this.listeners.get(type)?.delete(listener); }
  send(value) { this.sent.push(value); }
  close() { this.closeCalls += 1; this.readyState = 3; }
  emit(type, event = {}) {
    if (type === "open") this.readyState = 1;
    if (type === "close") this.readyState = 3;
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }
}

const harness = (options = {}) => {
  const sockets = [];
  const transport = new WebSocketNostrReadTransport({
    relayUrl: "wss://relay.test/read",
    openTimeoutMs: 100,
    readTimeoutMs: 100,
    maxEvents: 10,
    maxMessageBytes: 10_000,
    maxAccumulatedBytes: 50_000,
    subscriptionIdFactory: () => "test-subscription",
    webSocketFactory: (url) => {
      const socket = new FakeWebSocket(url);
      sockets.push(socket);
      return socket;
    },
    ...options
  });
  return { transport, sockets };
};

const begin = (options, filter = { kinds: [0, 1] }) => {
  const state = harness(options);
  const result = state.transport.read(filter);
  assert.equal(state.sockets.length, 1);
  return { ...state, socket: state.sockets[0], result };
};

const frame = (socket, value) => socket.emit("message", { data: JSON.stringify(value) });
const signed = (overrides = {}) => ({
  id: "e".repeat(64), pubkey: "a".repeat(64), created_at: 1, kind: 1, tags: [], content: "hello",
  sig: "f".repeat(128), ...overrides
});

test("explicit wss relay URL is canonicalized and the API is read only", () => {
  const { transport } = harness({ relayUrl: "wss://relay.test" });
  assert.equal(transport.relayUrl, "wss://relay.test/");
  assert.deepEqual(Object.getOwnPropertyNames(WebSocketNostrReadTransport.prototype), ["constructor", "read"]);
  for (const operation of ["publish", "sign", "send", "auth", "request", "readAssertion"]) assert.equal(transport[operation], undefined);
  assert.equal(Object.isFrozen(transport), true);
});

test("relay URL must be explicit wss without credentials or fragments", () => {
  for (const relayUrl of [undefined, "", "not a url", "http://relay.test", "https://relay.test", "ws://localhost", "javascript:alert(1)", "file:///tmp/relay", "data:text/plain,x", "wss://user@relay.test", "wss://user:pass@relay.test", "wss://relay.test/#fragment", "wss://relay.test/#"]) {
    assert.throws(() => new WebSocketNostrReadTransport({ relayUrl }), TypeError);
  }
});

test("constructor bounds and injection seams fail closed", () => {
  for (const field of ["openTimeoutMs", "readTimeoutMs", "maxEvents", "maxMessageBytes", "maxAccumulatedBytes"]) {
    for (const value of [0, -1, 1.5, Infinity, "1"]) assert.throws(() => harness({ [field]: value }), TypeError);
  }
  assert.throws(() => harness({ webSocketFactory: null }), TypeError);
  assert.throws(() => harness({ subscriptionIdFactory: null }), TypeError);
  assert.throws(() => harness({ subscriptionIdFactory: () => "contains spaces" }).transport.read({ kinds: [1] }), TypeError);
});

test("injected missing WebSocket and malformed factory results fail explicitly", async () => {
  const unavailable = harness({
    webSocketFactory: () => { throw new Error("WebSocket is unavailable; inject a WebSocket factory"); }
  });
  await assert.rejects(unavailable.transport.read({ kinds: [1] }), {
    name: "Error",
    message: "WebSocket is unavailable; inject a WebSocket factory"
  });
  assert.deepEqual(unavailable.sockets, []);
  await assert.rejects(harness({ webSocketFactory: () => ({}) }).transport.read({ kinds: [1] }), {
    name: "TypeError",
    message: "WebSocket factory must return a WebSocket-compatible object"
  });
});

test("REQ forwards the validated filter exactly and EOSE returns collected raw events", async () => {
  const input = { authors: ["AB12"], kinds: [1], since: 0, limit: 2 };
  const { socket, result } = begin({}, input);
  socket.emit("open");
  assert.equal(socket.url, "wss://relay.test/read");
  assert.deepEqual(JSON.parse(socket.sent[0]), ["REQ", "test-subscription", { authors: ["ab12"], kinds: [1], since: 0, limit: 2 }]);
  const event = { relay: "data remains raw" };
  frame(socket, ["EVENT", "test-subscription", event]);
  frame(socket, ["EOSE", "test-subscription"]);
  assert.deepEqual(await result, [event]);
  assert.deepEqual(JSON.parse(socket.sent[1]), ["CLOSE", "test-subscription"]);
  assert.equal(socket.closeCalls, 1);
  assert.equal([...socket.listeners.values()].every((listeners) => listeners.size === 0), true);
  assert.deepEqual(input, { authors: ["AB12"], kinds: [1], since: 0, limit: 2 });
});

test("maximum event count completes and cleans up deterministically", async () => {
  const { socket, result } = begin({ maxEvents: 1 });
  socket.emit("open");
  frame(socket, ["EVENT", "test-subscription", { first: true }]);
  assert.deepEqual(await result, [{ first: true }]);
  assert.deepEqual(socket.sent.map(JSON.parse), [
    ["REQ", "test-subscription", { kinds: [0, 1] }],
    ["CLOSE", "test-subscription"]
  ]);
  assert.equal(socket.closeCalls, 1);
});

test("wrong subscription EVENT and EOSE frames fail safely", async () => {
  for (const value of [["EVENT", "wrong", {}], ["EOSE", "wrong"]]) {
    const { socket, result } = begin();
    socket.emit("open");
    frame(socket, value);
    await assert.rejects(result, /wrong subscription id/);
    assert.deepEqual(JSON.parse(socket.sent.at(-1)), ["CLOSE", "test-subscription"]);
    assert.equal(socket.closeCalls, 1);
  }
});

test("malformed JSON, malformed shapes, unknown frames, and NOTICE fail safely", async () => {
  const cases = [
    { data: "{" },
    { data: JSON.stringify({ type: "EVENT" }) },
    { data: JSON.stringify(["EVENT", "test-subscription"]) },
    { data: JSON.stringify(["EVENT", "test-subscription", []]) },
    { data: JSON.stringify(["EOSE", "test-subscription", "extra"]) },
    { data: JSON.stringify(["NOTICE", 42]) },
    { data: JSON.stringify(["NOTICE", "denied"]) },
    { data: JSON.stringify(["OK", true]) },
    { data: new Uint8Array([1, 2]) }
  ];
  for (const message of cases) {
    const { socket, result } = begin();
    socket.emit("open");
    socket.emit("message", message);
    await assert.rejects(result);
    assert.equal(socket.closeCalls, 1);
  }
});

test("individual and accumulated message size bounds fail safely", async () => {
  const oversized = begin({ maxMessageBytes: 5 });
  oversized.socket.emit("open");
  frame(oversized.socket, ["EOSE", "test-subscription"]);
  await assert.rejects(oversized.result, /message exceeds size limit/);

  const accumulated = begin({ maxAccumulatedBytes: 45 });
  accumulated.socket.emit("open");
  frame(accumulated.socket, ["EVENT", "test-subscription", {}]);
  frame(accumulated.socket, ["EVENT", "test-subscription", {}]);
  await assert.rejects(accumulated.result, /accumulated size limit/);
  assert.equal(accumulated.socket.closeCalls, 1);
});

test("connection failure and premature close surface and clean up", async () => {
  const failed = begin();
  failed.socket.emit("error");
  await assert.rejects(failed.result, /connection failed/);
  assert.deepEqual(failed.socket.sent, []);
  assert.equal(failed.socket.closeCalls, 1);

  const closed = begin();
  closed.socket.emit("open");
  closed.socket.emit("close");
  await assert.rejects(closed.result, /closed before read completed/);
  assert.equal(closed.socket.closeCalls, 1);
});

test("relay data before REQ and duplicate open signals are protocol failures", async () => {
  const early = begin();
  frame(early.socket, ["EOSE", "test-subscription"]);
  await assert.rejects(early.result, /before the read request/);
  assert.deepEqual(early.socket.sent, []);

  const duplicate = begin();
  duplicate.socket.emit("open");
  duplicate.socket.emit("open");
  await assert.rejects(duplicate.result, /opened more than once/);
  assert.deepEqual(JSON.parse(duplicate.socket.sent.at(-1)), ["CLOSE", "test-subscription"]);
});

test("open and overall read timeouts are bounded and clean up", async () => {
  const unopened = begin({ openTimeoutMs: 5, readTimeoutMs: 50 });
  await assert.rejects(unopened.result, /open timed out/);
  assert.equal(unopened.socket.closeCalls, 1);

  const unfinished = begin({ openTimeoutMs: 50, readTimeoutMs: 5 });
  unfinished.socket.emit("open");
  await assert.rejects(unfinished.result, /read timed out/);
  assert.deepEqual(JSON.parse(unfinished.socket.sent.at(-1)), ["CLOSE", "test-subscription"]);
  assert.equal(unfinished.socket.closeCalls, 1);
});

test("raw relay events still require canonical adapter validation", async () => {
  for (const event of [signed({ kind: 99 }), signed({ privateKey: "rejected" })]) {
    const { transport, sockets } = harness();
    const adapterResult = NostrPublicReadAdapter.create({ viewerId: "a".repeat(64), transport });
    sockets[0].emit("open");
    frame(sockets[0], ["EVENT", "test-subscription", event]);
    frame(sockets[0], ["EOSE", "test-subscription"]);
    await assert.rejects(adapterResult, TypeError);
  }
});

test("explicit transport success remains social-only and cannot grant authority", async () => {
  const { transport, sockets } = harness();
  const adapterResult = NostrPublicReadAdapter.create({ viewerId: "a".repeat(64), transport });
  sockets[0].emit("open");
  frame(sockets[0], ["EVENT", "test-subscription", signed()]);
  frame(sockets[0], ["EOSE", "test-subscription"]);
  const adapter = await adapterResult;
  const data = createSocialDataService(adapter).load();
  assert.equal(adapter.readAssertion, undefined);
  assert.equal(data.statuses["a".repeat(64)], AccessStatus.LIMITED);
  assert.equal(data.externalAssertions["a".repeat(64)].valid, false);
});

test("relay failure cannot create a social adapter or authority result", async () => {
  const { transport, sockets } = harness();
  const adapterResult = NostrPublicReadAdapter.create({ viewerId: "a".repeat(64), transport });
  sockets[0].emit("error");
  await assert.rejects(adapterResult, /connection failed/);
});
