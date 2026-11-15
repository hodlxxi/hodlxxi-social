import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { SESSION_COOKIE_NAME } from "../src/server/social-oauth-cookie.mjs";
import {
  createSocialOAuthBff,
  SOCIAL_MESSAGE_TRANSPORT_ROUTE
} from "../src/server/social-oauth-bff.mjs";

const fixture = JSON.parse(readFileSync(
  new URL("./fixtures/social_messaging_phase3_routing_v1.json", import.meta.url),
  "utf8"
));
const wire = fixture.envelopeWire;
const envelope = JSON.parse(wire);
const deviceHandle = envelope.recipientDeviceHandles[0];
const subject = "a".repeat(64);
const sessionId = "s".repeat(43);
const cookie = SESSION_COOKIE_NAME + "=" + sessionId;
const capability = "rc_" + "b".repeat(43);
const origin = "https://social.example";
const config = {publicOrigin: origin};

const make = ({level = "full", transport, authorityError = false} = {}) => {
  const sessions = createBoundedStore({ttlSeconds: 3600, capacity: 3, now: () => 0});
  sessions.create(sessionId, {
    subject,
    viewerAccessToken: "human-private-token"
  });
  const calls = [];
  const backend = transport ?? {
    async submitForViewer(input) {
      calls.push(["submit", input]);
      return {state: "accepted", messageId: envelope.messageId};
    },
    async listForViewer(input) {
      calls.push(["inbox", input]);
      return {state: "available", messages: [wire]};
    }
  };
  const bff = createSocialOAuthBff({
    config, pendingTransactions: {}, sessions, oauthClient: {},
    ...(transport === null ? {} : {messagingTransportClient: backend}),
    authorityReader: async () => {
      if (authorityError) throw Error("authority unavailable");
      return {valid: true, status: level, subject};
    }
  });
  return {bff, calls};
};
const post = (headers = {}, body = wire) => ({
  method: "POST", url: SOCIAL_MESSAGE_TRANSPORT_ROUTE,
  headers: {cookie, origin, "content-type": "application/json",
    "x-hodlxxi-recipient-capability": capability, ...headers},
  body
});
const get = (headers = {}) => ({
  method: "GET", url: SOCIAL_MESSAGE_TRANSPORT_ROUTE,
  headers: {cookie, "x-hodlxxi-message-device-handle": deviceHandle, ...headers}
});

test("authenticated Full sends only exact canonical encrypted wire to backend", async () => {
  const {bff, calls} = make();
  const result = await bff(post());
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), {state: "accepted", messageId: envelope.messageId});
  assert.deepEqual(calls, [["submit", {
    viewerAccessToken: "human-private-token",
    expectedSubject: subject,
    recipientCapability: capability,
    envelopeWire: wire
  }]]);
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.doesNotMatch(result.body, /human-private-token|rc_b/);
});

test("inbox delegates exact device authorization and returns only ciphertext", async () => {
  const {bff, calls} = make();
  const result = await bff(get());
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), {state: "available", messages: [wire]});
  assert.deepEqual(calls, [["inbox", {
    viewerAccessToken: "human-private-token",
    expectedSubject: subject,
    deviceHandle
  }]]);
  assert.doesNotMatch(result.body, /human-private-token/);
});

test("no backend, Limited, authority failure, or anonymous session never reaches transport", async () => {
  for (const mode of [
    {transport: null, expected: 503}, {level: "limited", expected: 403},
    {authorityError: true, expected: 403}
  ]) {
    const {bff} = make(mode);
    for (const req of [post(), get()]) {
      const result = await bff(req);
      assert.equal(result.status, mode.expected);
      assert.deepEqual(JSON.parse(result.body), {state: "unavailable"});
    }
  }
  const {bff} = make();
  assert.equal((await bff({...post(), headers: {origin}})).status, 401);
  assert.equal((await bff({...get(), headers: {}})).status, 401);
});

test("cross-origin post, malformed wire, wrong capability and malformed device all deny", async () => {
  const {bff, calls} = make();
  for (const request of [
    post({origin: "https://foreign.example"}),
    post({}, "{}"),
    post({"x-hodlxxi-recipient-capability": "bad"}),
    post({"content-type": "text/plain"}),
    get({"x-hodlxxi-message-device-handle": "not-a-device"})
  ]) {
    const response = await bff(request);
    assert.ok([400, 403].includes(response.status));
    assert.deepEqual(JSON.parse(response.body), {state: "unavailable"});
  }
  assert.equal(calls.length, 0);
});

test("malformed or cross-device backend output cannot be reported as success", async () => {
  const {bff} = make({transport: {
    async submitForViewer() { return {state: "accepted", messageId: "m_" + "z".repeat(43)}; },
    async listForViewer() { return {state: "available", messages: ["{}"]}; }
  }});
  assert.equal((await bff(post())).status, 503);
  assert.equal((await bff(get())).status, 503);

  const {bff: other} = make({transport: {
    async submitForViewer() { return {state: "accepted", messageId: envelope.messageId}; },
    async listForViewer() { return {state: "available", messages: [wire]}; }
  }});
  const differentDevice = "d_" + "z".repeat(22);
  assert.equal((await other(get({"x-hodlxxi-message-device-handle": differentDevice}))).status, 503);
});
