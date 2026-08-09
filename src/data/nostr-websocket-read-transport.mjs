import { validatePublicRelayFilter } from "../nostr.mjs";

const OPEN = 1;
const DEFAULT_OPEN_TIMEOUT_MS = 5_000;
const DEFAULT_READ_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_EVENTS = 100;
const DEFAULT_MAX_MESSAGE_BYTES = 1_000_000;
const DEFAULT_MAX_ACCUMULATED_BYTES = 5_000_000;
const SUBSCRIPTION_ID = /^[A-Za-z0-9_-]{1,64}$/;
let nextSubscription = 0;

const defaultSubscriptionId = () => `social-read-${++nextSubscription}`;

const defaultWebSocketFactory = (relayUrl) => {
  if (typeof globalThis.WebSocket !== "function") throw new Error("WebSocket is unavailable; inject a WebSocket factory");
  return new globalThis.WebSocket(relayUrl);
};

function validateRelayUrl(value) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError("explicit relay URL is required");
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError("relay URL is malformed"); }
  if (parsed.protocol !== "wss:") throw new TypeError("relay URL must use wss");
  if (!parsed.hostname) throw new TypeError("relay URL must include a hostname");
  if (parsed.username || parsed.password) throw new TypeError("relay URL must not contain credentials");
  if (value.includes("#")) throw new TypeError("relay URL must not contain a fragment");
  return parsed.href;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive integer`);
  return value;
}

function validateSubscriptionId(value) {
  if (typeof value !== "string" || !SUBSCRIPTION_ID.test(value)) throw new TypeError("subscription id must be an opaque token");
  return value;
}

function requireSocket(value) {
  if (!value || typeof value.addEventListener !== "function" || typeof value.removeEventListener !== "function" ||
      typeof value.send !== "function" || typeof value.close !== "function" || typeof value.readyState !== "number") {
    throw new TypeError("WebSocket factory must return a WebSocket-compatible object");
  }
  return value;
}

export class WebSocketNostrReadTransport {
  constructor({
    relayUrl,
    openTimeoutMs = DEFAULT_OPEN_TIMEOUT_MS,
    readTimeoutMs = DEFAULT_READ_TIMEOUT_MS,
    maxEvents = DEFAULT_MAX_EVENTS,
    maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES,
    maxAccumulatedBytes = DEFAULT_MAX_ACCUMULATED_BYTES,
    webSocketFactory = defaultWebSocketFactory,
    subscriptionIdFactory = defaultSubscriptionId
  } = {}) {
    if (typeof webSocketFactory !== "function") throw new TypeError("WebSocket factory must be a function");
    if (typeof subscriptionIdFactory !== "function") throw new TypeError("subscription id factory must be a function");
    this.relayUrl = validateRelayUrl(relayUrl);
    this.openTimeoutMs = positiveInteger(openTimeoutMs, "open timeout");
    this.readTimeoutMs = positiveInteger(readTimeoutMs, "read timeout");
    this.maxEvents = positiveInteger(maxEvents, "maximum event count");
    this.maxMessageBytes = positiveInteger(maxMessageBytes, "maximum message size");
    this.maxAccumulatedBytes = positiveInteger(maxAccumulatedBytes, "maximum accumulated data size");
    this.webSocketFactory = webSocketFactory;
    this.subscriptionIdFactory = subscriptionIdFactory;
    Object.freeze(this);
  }

  read(filter) {
    const validatedFilter = validatePublicRelayFilter(filter);
    const subscriptionId = validateSubscriptionId(this.subscriptionIdFactory());
    let socket;
    try { socket = requireSocket(this.webSocketFactory(this.relayUrl)); } catch (error) { return Promise.reject(error); }

    return new Promise((resolve, reject) => {
      const events = [];
      let accumulatedBytes = 0;
      let reqSent = false;
      let settled = false;

      const removeListeners = () => {
        socket.removeEventListener("open", onOpen);
        socket.removeEventListener("message", onMessage);
        socket.removeEventListener("error", onError);
        socket.removeEventListener("close", onClose);
      };
      const cleanup = () => {
        clearTimeout(openTimer);
        clearTimeout(readTimer);
        removeListeners();
        if (reqSent && socket.readyState === OPEN) {
          try { socket.send(JSON.stringify(["CLOSE", subscriptionId])); } catch {}
        }
        try { socket.close(); } catch {}
      };
      const finish = (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) reject(error);
        else resolve(events);
      };
      const fail = (message) => finish(new Error(message));

      function onOpen() {
        if (reqSent) return fail("Nostr relay opened more than once");
        clearTimeout(openTimer);
        try {
          socket.send(JSON.stringify(["REQ", subscriptionId, validatedFilter]));
          reqSent = true;
        } catch { fail("failed to send Nostr read request"); }
      }

      const onMessage = (message) => {
        if (!reqSent) return fail("Nostr relay sent data before the read request");
        if (typeof message?.data !== "string") return fail("Nostr relay message must be text");
        const messageBytes = new TextEncoder().encode(message.data).byteLength;
        if (messageBytes > this.maxMessageBytes) return fail("Nostr relay message exceeds size limit");
        accumulatedBytes += messageBytes;
        if (accumulatedBytes > this.maxAccumulatedBytes) return fail("Nostr relay data exceeds accumulated size limit");

        let frame;
        try { frame = JSON.parse(message.data); } catch { return fail("Nostr relay message is malformed JSON"); }
        if (!Array.isArray(frame) || typeof frame[0] !== "string") return fail("malformed Nostr relay frame");
        if (frame[0] === "EVENT") {
          if (frame.length !== 3 || typeof frame[1] !== "string" || !frame[2] || typeof frame[2] !== "object" || Array.isArray(frame[2])) return fail("malformed Nostr EVENT frame");
          if (frame[1] !== subscriptionId) return fail("Nostr EVENT has wrong subscription id");
          events.push(frame[2]);
          if (events.length >= this.maxEvents) finish();
        } else if (frame[0] === "EOSE") {
          if (frame.length !== 2 || typeof frame[1] !== "string") return fail("malformed Nostr EOSE frame");
          if (frame[1] !== subscriptionId) return fail("Nostr EOSE has wrong subscription id");
          finish();
        } else if (frame[0] === "NOTICE") {
          if (frame.length !== 2 || typeof frame[1] !== "string") return fail("malformed Nostr NOTICE frame");
          fail(`Nostr relay notice: ${frame[1]}`);
        } else {
          fail("unsupported Nostr relay frame");
        }
      };

      function onError() { fail("Nostr relay connection failed"); }
      function onClose() { fail("Nostr relay closed before read completed"); }

      const openTimer = setTimeout(() => fail("Nostr relay open timed out"), this.openTimeoutMs);
      const readTimer = setTimeout(() => fail("Nostr relay read timed out"), this.readTimeoutMs);
      socket.addEventListener("open", onOpen);
      socket.addEventListener("message", onMessage);
      socket.addEventListener("error", onError);
      socket.addEventListener("close", onClose);
    });
  }
}
