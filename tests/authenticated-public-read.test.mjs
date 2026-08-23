import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  canonicalNostrRelayUrl,
  createPendingAuthenticatedPublicRead,
  createUnavailableAuthenticatedPublicRead,
  loadAuthenticatedPublicRead,
  readAuthenticatedNostrEvents
} from "../web/authenticated-public-read.mjs";

const subject = "a".repeat(64);
const relayUrl = "wss://relay.example/";

const event = ({ kind, id, createdAt, content, pubkey = subject }) => ({
  id,
  pubkey,
  created_at: createdAt,
  kind,
  tags: [],
  content,
  sig: "f".repeat(128)
});

class FakeSocket {
  constructor() {
    this.readyState = 0;
    this.listeners = new Map();
    this.sent = [];
    this.closed = 0;
  }

  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) ?? new Set();
    listeners.add(listener);
    this.listeners.set(name, listeners);
  }

  removeEventListener(name, listener) {
    this.listeners.get(name)?.delete(listener);
  }

  send(value) {
    this.sent.push(value);
  }

  close() {
    this.closed += 1;
    this.readyState = 3;
  }

  emit(name, value = {}) {
    if (name === "open") this.readyState = 1;
    for (const listener of [...(this.listeners.get(name) ?? [])]) listener(value);
  }
}

test("explicit relay URLs are canonical wss endpoints without credentials or fragments", () => {
  assert.equal(canonicalNostrRelayUrl("wss://relay.example"), relayUrl);
  assert.equal(canonicalNostrRelayUrl("wss://relay.example/path?x=1"), "wss://relay.example/path?x=1");

  for (const value of [
    "",
    "ws://relay.example",
    "https://relay.example",
    "wss://user:pass@relay.example",
    "wss://relay.example/#fragment",
    "wss://relay.example./",
    " wss://relay.example"
  ]) {
    assert.throws(() => canonicalNostrRelayUrl(value), /invalid Nostr relay URL/);
  }
});

test("pending and unavailable states are exact immutable no-data states", () => {
  assert.deepEqual(createPendingAuthenticatedPublicRead(), {
    relayHost: null,
    profileState: "loading",
    profile: null,
    notesState: "loading",
    notes: []
  });
  assert.deepEqual(createUnavailableAuthenticatedPublicRead(), {
    relayHost: null,
    profileState: "unavailable",
    profile: null,
    notesState: "unavailable",
    notes: []
  });
  assert.ok(Object.isFrozen(createPendingAuthenticatedPublicRead()));
  assert.ok(Object.isFrozen(createUnavailableAuthenticatedPublicRead().notes));
});

test("one production read sends one exact subject filter and closes at EOSE", async () => {
  const socket = new FakeSocket();
  let selectedRelay;
  const pending = readAuthenticatedNostrEvents(
    {
      relayUrl,
      subject,
      kind: 1,
      limit: 2
    },
    {
      webSocketFactory(value) {
        selectedRelay = value;
        return socket;
      },
      subscriptionIdFactory: () => "fixed-read"
    }
  );

  socket.emit("open");
  assert.equal(selectedRelay, relayUrl);
  assert.deepEqual(JSON.parse(socket.sent[0]), [
    "REQ",
    "fixed-read",
    {
      authors: [subject],
      kinds: [1],
      limit: 2
    }
  ]);

  const note = event({
    kind: 1,
    id: "1".repeat(64),
    createdAt: 1_700_000_000,
    content: "hello"
  });
  socket.emit("message", {
    data: JSON.stringify(["EVENT", "fixed-read", note])
  });
  socket.emit("message", {
    data: JSON.stringify(["EOSE", "fixed-read"])
  });

  assert.deepEqual(await pending, [note]);
  assert.deepEqual(JSON.parse(socket.sent[1]), ["CLOSE", "fixed-read"]);
  assert.equal(socket.closed, 1);
});

test("transport rejects invalid bounds before connection and sanitizes relay-controlled failures", async () => {
  let sockets = 0;
  for (const input of [
    { subject: "A".repeat(64), kind: 1, limit: 1 },
    { subject, kind: 2, limit: 1 },
    { subject, kind: 0, limit: 5 },
    { subject, kind: 1, limit: 11 }
  ]) {
    await assert.rejects(
      readAuthenticatedNostrEvents(
        { relayUrl, ...input },
        {
          webSocketFactory() {
            sockets += 1;
            return new FakeSocket();
          }
        }
      )
    );
  }
  assert.equal(sockets, 0);

  const socket = new FakeSocket();
  const pending = readAuthenticatedNostrEvents(
    { relayUrl, subject, kind: 1, limit: 1 },
    {
      webSocketFactory: () => socket,
      subscriptionIdFactory: () => "notice-read"
    }
  );
  socket.emit("open");
  socket.emit("message", {
    data: JSON.stringify(["NOTICE", "relay-private-diagnostic"])
  });
  await assert.rejects(
    pending,
    (error) =>
      error.message === "authenticated Nostr read unavailable" &&
      !error.message.includes("private")
  );
});

test("profile and own notes are independently bounded, normalized, and ordered", async () => {
  const calls = [];
  const result = await loadAuthenticatedPublicRead(
    { subject, relayUrl },
    {
      readEvents: async (input) => {
        calls.push(input);
        return input.kind === 0
          ? [
              event({
                kind: 0,
                id: "2".repeat(64),
                createdAt: 1_700_000_000,
                content: JSON.stringify({ name: "Old Name" })
              }),
              event({
                kind: 0,
                id: "1".repeat(64),
                createdAt: 1_700_000_001,
                content: JSON.stringify({
                  display_name: "  Ada\u0000  Lovelace  ",
                  about: "Public profile only"
                })
              })
            ]
          : [
              event({
                kind: 1,
                id: "4".repeat(64),
                createdAt: 1_700_000_002,
                content: "newest"
              }),
              event({
                kind: 1,
                id: "3".repeat(64),
                createdAt: 1_700_000_001,
                content: "older"
              })
            ];
      },
      verifyEvent: async (value) => Object.freeze(value)
    }
  );

  assert.deepEqual(calls, [
    { subject, relayUrl, kind: 0, limit: 4 },
    { subject, relayUrl, kind: 1, limit: 10 }
  ]);
  assert.deepEqual(result, {
    relayHost: "relay.example",
    profileState: "available",
    profile: {
      displayName: "Ada Lovelace",
      about: "Public profile only",
      eventId: "1".repeat(64),
      createdAt: "2023-11-14T22:13:21.000Z"
    },
    notesState: "available",
    notes: [
      {
        id: "4".repeat(64),
        body: "newest",
        createdAt: "2023-11-14T22:13:22.000Z"
      },
      {
        id: "3".repeat(64),
        body: "older",
        createdAt: "2023-11-14T22:13:21.000Z"
      }
    ]
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.profile));
  assert.ok(Object.isFrozen(result.notes));
  assert.ok(Object.isFrozen(result.notes[0]));
});

test("profile and note failures settle independently and never expose off-subject data", async () => {
  const note = event({
    kind: 1,
    id: "5".repeat(64),
    createdAt: 1_700_000_000,
    content: "verified note"
  });
  const result = await loadAuthenticatedPublicRead(
    { subject, relayUrl },
    {
      readEvents: async ({ kind }) => {
        if (kind === 0) throw new Error("private relay failure");
        return [note];
      },
      verifyEvent: async (value) => Object.freeze(value)
    }
  );
  assert.equal(result.profileState, "unavailable");
  assert.equal(result.profile, null);
  assert.equal(result.notesState, "available");
  assert.equal(result.notes[0].body, "verified note");
  assert.doesNotMatch(JSON.stringify(result), /private relay failure/);

  const offSubject = await loadAuthenticatedPublicRead(
    { subject, relayUrl },
    {
      readEvents: async ({ kind }) => [event({
        kind,
        id: String(kind).repeat(64),
        createdAt: 1_700_000_000,
        content: kind === 0 ? "{}" : "hostile",
        pubkey: "b".repeat(64)
      })],
      verifyEvent: async (value) => Object.freeze(value)
    }
  );
  assert.equal(offSubject.profileState, "unavailable");
  assert.equal(offSubject.notesState, "unavailable");
  assert.deepEqual(offSubject.notes, []);
});

test("hex-shaped but unsigned relay records cannot enter the default production read", async () => {
  const result = await loadAuthenticatedPublicRead(
    { subject, relayUrl },
    {
      readEvents: async ({ kind }) => [event({
        kind,
        id: String(kind).repeat(64),
        createdAt: 1_700_000_000,
        content: kind === 0 ? "{}" : "not signed"
      })]
    }
  );

  assert.equal(result.profileState, "unavailable");
  assert.equal(result.notesState, "unavailable");
  assert.equal(result.profile, null);
  assert.deepEqual(result.notes, []);
});

test("production browser read boundary stays read-only and cannot select either relay", async () => {
  const [entrySource, productSource, readSource, verifierSource] = await Promise.all([
    readFile(new URL("../web/auth-entry.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/auth-product.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/authenticated-public-read.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/nostr-event-verifier.mjs", import.meta.url), "utf8")
  ]);
  const productionSources = [entrySource, productSource, readSource, verifierSource];

  for (const source of productionSources) {
    assert.doesNotMatch(source, /\b(?:localStorage|sessionStorage|indexedDB)\b/);
    assert.doesNotMatch(source, /document\.cookie/);
    assert.doesNotMatch(source, /\b(?:privateKey|secretKey|signEvent)\b/);
    assert.doesNotMatch(source, /\.publish\s*\(/);
  }

  assert.match(readSource, /new globalThis\.WebSocket\(relayUrl\)/);
  assert.match(readSource, /\["REQ", subscriptionId, filter\]/);
  assert.match(readSource, /\["CLOSE", subscriptionId\]/);
  assert.doesNotMatch(readSource, /\["EVENT",/);
  assert.doesNotMatch(readSource, /\bfetch\s*\(/);
  assert.doesNotMatch(readSource, /process\.env/);

  assert.doesNotMatch(verifierSource, /\bWebSocket\b/);
  assert.doesNotMatch(verifierSource, /\bfetch\s*\(/);
  assert.doesNotMatch(verifierSource, /process\.env/);

  const fetchedPaths = [...entrySource.matchAll(/fetchImpl\("([^"]+)"/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(fetchedPaths, [
    "/auth/authority",
    "/auth/logout",
    "/auth/session",
    "/auth/social-publish-config",
    "/auth/social-read-config"
  ]);
  assert.doesNotMatch(entrySource, /\bWebSocket\b/);
  assert.doesNotMatch(productSource, /\b(?:fetch|WebSocket)\s*\(/);
});
