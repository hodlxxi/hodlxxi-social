import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  AUTHENTICATED_SIGNER_STATES,
  connectAuthenticatedNip07Signer,
  createAuthenticatedNoteContent,
  createAuthenticatedProfileContent,
  publishAuthenticatedNote,
  publishAuthenticatedProfile,
  publishSignedNostrEvent,
  signAuthenticatedNostrEvent
} from "../web/authenticated-public-write.mjs";

const subject = "a".repeat(64);
const otherSubject = "b".repeat(64);
const eventId = "c".repeat(64);

const signedEvent = (patch = {}) => Object.freeze({
  id: eventId,
  pubkey: subject,
  created_at: 1_777_777_777,
  kind: 1,
  tags: Object.freeze([]),
  content: "Hello Social",
  sig: "d".repeat(128),
  ...patch
});

const immediateTimers = () => ({
  setTimer: () => 7,
  clearTimer: () => {}
});

test("profile and note inputs normalize bounded public text only", () => {
  assert.equal(
    createAuthenticatedProfileContent({
      displayName: "  Alice\u0000  Social  ",
      about: "Public\nprofile"
    }),
    JSON.stringify({
      display_name: "Alice Social",
      about: "Public profile"
    })
  );

  assert.equal(
    createAuthenticatedNoteContent("  signed\npublic note  "),
    "signed\npublic note"
  );

  for (const input of [
    { displayName: "", about: "" },
    { displayName: "x".repeat(81), about: "ok" },
    { displayName: "ok", about: "x".repeat(281) },
    { displayName: null, about: "ok" }
  ]) {
    assert.throws(
      () => createAuthenticatedProfileContent(input),
      /publication unavailable/
    );
  }

  for (const value of [
    "",
    "\u0000hostile",
    "x".repeat(5_001),
    null
  ]) {
    assert.throws(
      () => createAuthenticatedNoteContent(value),
      /publication unavailable/
    );
  }
});

test("signer connection is explicit exact-subject and retains no provider", async () => {
  let resolutions = 0;
  let calls = 0;
  const provider = {
    async getPublicKey() {
      calls += 1;
      return subject;
    }
  };

  const result = await connectAuthenticatedNip07Signer(
    { subject },
    {
      resolveProvider() {
        resolutions += 1;
        return provider;
      },
      ...immediateTimers()
    }
  );

  assert.deepEqual(result, {
    state: AUTHENTICATED_SIGNER_STATES.connected,
    publicKey: subject
  });
  assert.deepEqual(Object.keys(result), ["state", "publicKey"]);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(resolutions, 1);
  assert.equal(calls, 1);
  assert.equal(JSON.stringify(result).includes("provider"), false);

  const mismatch = await connectAuthenticatedNip07Signer(
    { subject },
    {
      resolveProvider: () => ({ getPublicKey: async () => otherSubject }),
      ...immediateTimers()
    }
  );
  assert.deepEqual(mismatch, {
    state: AUTHENTICATED_SIGNER_STATES.mismatch
  });
});

test("missing hostile and timed-out signers fail with fixed states", async () => {
  const hostile = "extension secret failure";
  const cases = [
    () => undefined,
    () => null,
    () => ({}),
    () => ({ getPublicKey: 1 }),
    () => { throw new Error(hostile); },
    () => Object.defineProperty({}, "getPublicKey", {
      get() { throw new Error(hostile); }
    })
  ];

  for (const resolveProvider of cases) {
    const result = await connectAuthenticatedNip07Signer(
      { subject },
      { resolveProvider, ...immediateTimers() }
    );
    assert.deepEqual(result, {
      state: AUTHENTICATED_SIGNER_STATES.unavailable
    });
    assert.doesNotMatch(JSON.stringify(result), /secret/);
  }

  let fire;
  const pending = connectAuthenticatedNip07Signer(
    { subject },
    {
      resolveProvider: () => ({
        getPublicKey: () => new Promise(() => {})
      }),
      timeoutMs: 1,
      setTimer(callback) {
        fire = callback;
        return 9;
      },
      clearTimer() {}
    }
  );
  await Promise.resolve();
  fire();
  assert.deepEqual(await pending, {
    state: AUTHENTICATED_SIGNER_STATES.unavailable
  });
});

test("one signing request rechecks the extension key and binds every event field", async () => {
  const calls = [];
  const candidate = signedEvent();
  const provider = {
    async getPublicKey() {
      calls.push("getPublicKey");
      return subject;
    },
    async signEvent(unsigned) {
      calls.push(["signEvent", structuredClone(unsigned)]);
      return candidate;
    }
  };
  let verified = 0;

  const result = await signAuthenticatedNostrEvent(
    {
      subject,
      kind: 1,
      content: "Hello Social",
      tags: [],
      createdAt: 1_777_777_777
    },
    {
      resolveProvider: () => provider,
      verifyEvent: async (value) => {
        verified += 1;
        assert.equal(value, candidate);
        return candidate;
      },
      ...immediateTimers()
    }
  );

  assert.equal(result, candidate);
  assert.equal(verified, 1);
  assert.deepEqual(calls, [
    "getPublicKey",
    ["signEvent", {
      created_at: 1_777_777_777,
      kind: 1,
      tags: [],
      content: "Hello Social"
    }]
  ]);
});

test("mismatched keys altered events and attacker thenables never publish", async () => {
  let signCalls = 0;
  let signGetterCalls = 0;
  const mismatchedProvider = {
    getPublicKey: async () => otherSubject
  };
  Object.defineProperty(mismatchedProvider, "signEvent", {
    get() {
      signGetterCalls += 1;
      return async () => {
        signCalls += 1;
        return signedEvent();
      };
    }
  });
  await assert.rejects(
    signAuthenticatedNostrEvent(
      {
        subject,
        kind: 1,
        content: "Hello Social",
        createdAt: 1_777_777_777
      },
      {
        resolveProvider: () => mismatchedProvider,
        verifyEvent: async (event) => event,
        ...immediateTimers()
      }
    ),
    /publication unavailable/
  );
  assert.equal(signCalls, 0);
  assert.equal(signGetterCalls, 0);

  for (const altered of [
    signedEvent({ content: "changed" }),
    signedEvent({ kind: 0 }),
    signedEvent({ created_at: 1_777_777_778 }),
    signedEvent({ pubkey: otherSubject })
  ]) {
    await assert.rejects(
      signAuthenticatedNostrEvent(
        {
          subject,
          kind: 1,
          content: "Hello Social",
          createdAt: 1_777_777_777
        },
        {
          resolveProvider: () => ({
            getPublicKey: async () => subject,
            signEvent: async () => altered
          }),
          verifyEvent: async () => altered,
          ...immediateTimers()
        }
      ),
      /publication unavailable/
    );
  }

  let thenCalls = 0;
  const attacker = {
    then() {
      thenCalls += 1;
    }
  };
  await assert.rejects(
    signAuthenticatedNostrEvent(
      {
        subject,
        kind: 1,
        content: "Hello Social",
        createdAt: 1_777_777_777
      },
      {
        resolveProvider: () => ({
          getPublicKey: () => subject,
          signEvent: () => attacker
        }),
        verifyEvent: async (event) => event,
        ...immediateTimers()
      }
    ),
    /publication unavailable/
  );
  assert.equal(thenCalls, 0);
});

class FakeSocket {
  constructor() {
    this.listeners = new Map();
    this.sent = [];
    this.closed = 0;
  }

  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }

  removeEventListener(name, callback) {
    if (this.listeners.get(name) === callback) this.listeners.delete(name);
  }

  send(value) {
    this.sent.push(value);
  }

  close() {
    this.closed += 1;
  }

  emit(name, value = {}) {
    this.listeners.get(name)?.(value);
  }
}

test("one relay publication sends one EVENT and accepts one exact OK", async () => {
  const socket = new FakeSocket();
  const event = signedEvent();
  const timers = [];
  const publication = publishSignedNostrEvent(
    {
      relayUrl: "wss://relay.example",
      event
    },
    {
      webSocketFactory(relayUrl) {
        assert.equal(relayUrl, "wss://relay.example/");
        return socket;
      },
      verifyEvent: async (value) => {
        assert.equal(value, event);
        return event;
      },
      setTimer(callback) {
        timers.push(callback);
        return timers.length;
      },
      clearTimer() {}
    }
  );

  await Promise.resolve();
  socket.emit("open");
  assert.deepEqual(JSON.parse(socket.sent[0]), ["EVENT", event]);
  socket.emit("message", {
    data: JSON.stringify(["OK", event.id, true, "accepted"])
  });

  assert.deepEqual(await publication, {
    accepted: true,
    eventId: event.id,
    relayHost: "relay.example"
  });
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.closed, 1);
});

test("relay rejection malformed acknowledgements and timeouts fail closed", async () => {
  const event = signedEvent();
  const frames = [
    ["OK", event.id, false, "blocked: private relay detail"],
    ["OK", otherSubject, true, ""],
    ["NOTICE", "hostile"],
    ["OK", event.id, true],
    { accepted: true }
  ];

  for (const frame of frames) {
    const socket = new FakeSocket();
    const publication = publishSignedNostrEvent(
      { relayUrl: "wss://relay.example/", event },
      {
        webSocketFactory: () => socket,
        verifyEvent: async () => event,
        setTimer: () => 1,
        clearTimer() {}
      }
    );
    await Promise.resolve();
    socket.emit("open");
    socket.emit("message", { data: JSON.stringify(frame) });
    await assert.rejects(
      publication,
      (error) => {
        assert.match(error.message, /publication unavailable/);
        assert.doesNotMatch(error.message, /private|hostile|blocked/);
        return true;
      }
    );
  }

  let fire;
  const socket = new FakeSocket();
  const timed = publishSignedNostrEvent(
    { relayUrl: "wss://relay.example/", event },
    {
      webSocketFactory: () => socket,
      verifyEvent: async () => event,
      setTimer(callback) {
        fire = callback;
        return 1;
      },
      clearTimer() {}
    }
  );
  await Promise.resolve();
  fire();
  await assert.rejects(timed, /publication unavailable/);
  assert.equal(socket.sent.length, 0);

  const prematureSocket = new FakeSocket();
  const premature = publishSignedNostrEvent(
    { relayUrl: "wss://relay.example/", event },
    {
      webSocketFactory: () => prematureSocket,
      verifyEvent: async () => event,
      setTimer: () => 1,
      clearTimer() {}
    }
  );
  await Promise.resolve();
  prematureSocket.emit("message", {
    data: JSON.stringify(["OK", event.id, true, "accepted"])
  });
  await assert.rejects(premature, /publication unavailable/);
  assert.equal(prematureSocket.sent.length, 0);

  await assert.rejects(
    publishSignedNostrEvent(
      { relayUrl: "ws://relay.example/", event },
      { verifyEvent: async () => event }
    ),
    /publication unavailable/
  );
});

test("profile and note orchestration sign then publish one exact event", async () => {
  const calls = [];
  const profileEvent = signedEvent({ kind: 0, content: "profile" });
  const noteEvent = signedEvent();
  const receipt = Object.freeze({
    accepted: true,
    eventId,
    relayHost: "relay.example"
  });
  const signer = async (input) => {
    calls.push(["sign", input]);
    return input.kind === 0 ? profileEvent : noteEvent;
  };
  const publisher = async (input) => {
    calls.push(["publish", input]);
    return receipt;
  };
  const dependencies = {
    now: () => 1_777_777_777,
    signer,
    publisher
  };

  const profile = await publishAuthenticatedProfile(
    {
      subject,
      relayUrl: "wss://relay.example/",
      displayName: "Alice",
      about: "Public profile"
    },
    dependencies
  );
  const note = await publishAuthenticatedNote(
    {
      subject,
      relayUrl: "wss://relay.example/",
      content: "Hello Social"
    },
    dependencies
  );

  assert.deepEqual(profile, { event: profileEvent, receipt });
  assert.deepEqual(note, { event: noteEvent, receipt });
  assert.equal(calls.length, 4);
  assert.deepEqual(calls[0][1], {
    subject,
    kind: 0,
    content: JSON.stringify({
      display_name: "Alice",
      about: "Public profile"
    }),
    tags: [],
    createdAt: 1_777_777_777
  });
  assert.deepEqual(calls[1], ["publish", {
    relayUrl: "wss://relay.example/",
    event: profileEvent
  }]);
  assert.equal(calls[2][1].kind, 1);
  assert.equal(calls[2][1].content, "Hello Social");
  assert.deepEqual(calls[3], ["publish", {
    relayUrl: "wss://relay.example/",
    event: noteEvent
  }]);
});

test("authenticated write boundary has no key custody persistence or server path", async () => {
  const source = await readFile(
    new URL("../web/authenticated-public-write.mjs", import.meta.url),
    "utf8"
  );

  assert.match(source, /provider\.signEvent|"signEvent"/);
  assert.match(source, /\["EVENT", verified\]/);
  assert.doesNotMatch(
    source,
    /private.?key|nsec|secret.?key|localStorage|sessionStorage|indexedDB|document\.cookie|fetch\(|XMLHttpRequest|WebTransport|setInterval|retry|reconnect|HODLXXI_AUTHORITY|status\s*=\s*["']full/i
  );
});
