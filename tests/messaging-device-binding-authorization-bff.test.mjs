import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { webcrypto } from "node:crypto";
import {
  canonicalMessagingDeviceJson
} from "../web/messaging-device-authorization-v1.mjs";
import {
  createSocialOAuthBff,
  SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_CONFIG_ROUTE,
  SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
  SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
  SOCIAL_MESSAGING_DEVICE_BINDINGS_ROUTE
} from "../src/server/social-oauth-bff.mjs";
import {
  createUbidMessagingDeviceAuthorizationClient
} from "../src/server/ubid-messaging-device-client.mjs";
import { createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { SESSION_COOKIE_NAME } from "../src/server/social-oauth-cookie.mjs";
import { createHttpHandler } from "../scripts/hodlxxi-social-server.mjs";

const subject = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const viewerAccessToken = "viewer-private-token";
const deviceId = "22".repeat(32);
const requestId = "33".repeat(32);
const publicKey = "09" + "00".repeat(31);
const digest = "70aa19a24077c3365a836f0476660f0132ab7959615d2c8c67ba75afd9071d9c";
const eventId = "4fb89f90de1379e47893ad335c4839805be4265767d1972b7281aea2ef2e0ad0";
const signature =
  "6fb5dcbb6791eaf44bb2fa9282a1db21c702e88db58ab388d974baae4b082ff69" +
  "cfbfe4eb62fe36a8040fb9de010a1e6a9a2b6232332fac21d2d7a2a7e689570";
const content =
  '{"authorization":{"algorithm":"x25519-v1","bindingExpiresAt":"2026-10-08T22:29:59Z",' +
  '"bindingRecordSchema":"hodlxxi.social_messaging_device_binding_record.v1",' +
  '"bindingRecordVersion":1,"bindingValidFrom":"2026-09-08T22:29:59Z",' +
  '"bindingVersion":1,"deviceId":"' + deviceId + '","expiresAt":"2026-09-08T22:34:59Z",' +
  '"issuedAt":"2026-09-08T22:29:59Z","operation":"register","priorBindingId":null,' +
  '"publicKey":"' + publicKey + '","requestId":"' + requestId + '",' +
  '"schema":"hodlxxi.social_messaging_device_binding_authorization.v1","subject":"' + subject + '",' +
  '"version":1},"domain":"HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"}';
const claim = JSON.parse(content).authorization;
const tags = [
  ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
  ["semantic-digest", digest],
  ["request-id", requestId],
  ["action", "register"]
];
const signedEvent = {
  content, created_at: 1788906599, id: eventId, kind: 27236,
  pubkey: subject, sig: signature, tags
};
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const intentToken = [
  b64({ alg: "RS256", kid: "service-key", typ: "hodlxxi-device-binding-intent+jwt" }),
  b64({
    iss: "https://identity.example", sub: subject, iat: 1788906599, exp: 1788906899,
    jti: requestId,
    aud: "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1",
    tokenUse: "device_binding_authorization_intent",
    purpose: "social_messaging_device_binding_authorization_intent_v1",
    claimType: "lifecycle", action: "register", digest, eventId,
    signatureFormat: "nostr_event_id_bip340_v1"
  }),
  "signature"
].join(".");
const intent = {
  claim,
  claimType: "lifecycle",
  digest,
  expectedPubkey: subject,
  intentToken,
  schema: "hodlxxi.social_messaging_device_binding_authorization_intent.v1",
  signatureFormat: "nostr_event_id_bip340_v1",
  unsignedEvent: { content, created_at: 1788906599, kind: 27236, tags },
  version: 1
};
const result = {
  action: "register",
  active: true,
  authorizationExpiresAt: "2026-10-08T22:29:59Z",
  authorizationProofId: "hodlxxi-binding-authorization-v1-sha256:" + digest,
  authorizationValidFrom: "2026-09-08T22:29:59Z",
  bindingId: "6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d",
  bindingOperation: "register",
  bindingVersion: 1,
  deviceId,
  expiresAt: "2026-10-08T22:29:59Z",
  requestId,
  schema: "hodlxxi.social_messaging_device_binding_authorization_result.v1",
  validFrom: "2026-09-08T22:29:59Z",
  version: 1
};
const proposalPayload = canonicalMessagingDeviceJson({
  deviceId, expectedBindingId: null, operation: "register", publicKey, requestId
});
const signedEventPayload = canonicalMessagingDeviceJson(signedEvent);

const fixture = ({
  enabled = true,
  intentValue = intent,
  authorizationValue = result,
  authorizationFailure,
  now = () => 1_788_906_599_000
} = {}) => {
  const sessions = createBoundedStore({ ttlSeconds: 3600, capacity: 10, now: () => 0 });
  const sessionId = "session-authorization";
  sessions.create(sessionId, { subject, viewerAccessToken });
  const calls = [];
  const messagingDeviceClient = {
    currentForViewer: async () => ({
      schema: "hodlxxi.social_messaging_device_binding_snapshot.v1",
      version: 1, source: "hodlxxi-ubid", snapshotId: "sha256:" + "1".repeat(64),
      complete: true, issuedAt: 1, expiresAt: 2, activeDevices: []
    }),
    async applyForViewer(value) { calls.push(["legacy", value]); return {}; }
  };
  const messagingDeviceAuthorizationClient = enabled ? {
    async createIntentForViewer(value) { calls.push(["intent", value]); return structuredClone(intentValue); },
    async authorizeForViewer(value) {
      calls.push(["authorize", value]);
      if (authorizationFailure !== undefined) throw authorizationFailure;
      return structuredClone(authorizationValue);
    }
  } : undefined;
  const config = {
    publicOrigin: "https://social.example",
    authorityOrigin: "https://identity.example",
    callbackUri: "https://social.example/auth/callback",
    clientId: "social", scope: "openid", transactionTtlSeconds: 300,
    sessionTtlSeconds: 3600,
    messagingDevice: { enabled: true },
    messagingDeviceAuthorization: { enabled }
  };
  const bff = createSocialOAuthBff({
    config,
    pendingTransactions: createBoundedStore({ ttlSeconds: 300, capacity: 10, now: () => 0 }),
    sessions,
    oauthClient: {},
    authorityReader: async (candidate) => ({ subject: candidate, status: "full", valid: true }),
    messagingDeviceClient,
    messagingDeviceAuthorizationClient,
    now
  });
  return { bff, calls, cookie: `${SESSION_COOKIE_NAME}=${sessionId}` };
};

test("authorization feature is session-gated and reports only its enabled bit", async () => {
  for (const enabled of [false, true]) {
    const { bff, cookie } = fixture({ enabled });
    const denied = await bff({ method: "GET", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_CONFIG_ROUTE, headers: {} });
    assert.equal(denied.status, 401);
    const accepted = await bff({ method: "GET", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_CONFIG_ROUTE, headers: { cookie } });
    assert.deepEqual(JSON.parse(accepted.body), { enabled });
  }
});

test("BFF obtains the exact trusted intent and submits only event plus separate token", async () => {
  const { bff, calls, cookie } = fixture();
  const created = await bff({
    method: "POST",
    url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
    headers: { cookie, origin: "https://social.example", "content-type": "application/json" },
    body: proposalPayload
  });
  assert.equal(created.status, 200);
  assert.equal(JSON.parse(created.body).expectedPubkey, subject);
  assert.deepEqual(calls[0], ["intent", {
    viewerAccessToken, expectedSubject: subject, proposalPayload
  }]);

  const authorized = await bff({
    method: "POST",
    url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
    headers: {
      cookie, origin: "https://social.example", "content-type": "application/json",
      "x-hodlxxi-device-binding-intent": intentToken
    },
    body: signedEventPayload
  });
  assert.equal(authorized.status, 200);
  assert.deepEqual(JSON.parse(authorized.body), result);
  assert.deepEqual(calls[1], ["authorize", {
    viewerAccessToken, expectedSubject: subject, intentToken, signedEventPayload
  }]);
  assert.doesNotMatch(created.body + authorized.body, /viewer-private-token/);

  const retry = await bff({
    method: "POST",
    url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
    headers: {
      cookie, origin: "https://social.example", "content-type": "application/json",
      "x-hodlxxi-device-binding-intent": intentToken
    },
    body: signedEventPayload
  });
  assert.equal(retry.body, authorized.body);
});

test("malformed absent mismatched and expired UBID intent responses fail generically", async () => {
  const invalid = [];
  const missing = structuredClone(intent); delete missing.intentToken; invalid.push({ intentValue: missing });
  invalid.push({ intentValue: { ...structuredClone(intent), expectedPubkey: "b".repeat(64) } });
  invalid.push({ intentValue: { ...structuredClone(intent), intentToken: "not-a-token" } });
  invalid.push({ now: () => 1_788_906_899_000 });
  for (const options of invalid) {
    const { bff, calls, cookie } = fixture(options);
    const response = await bff({
      method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
      headers: { cookie, origin: "https://social.example", "content-type": "application/json" },
      body: proposalPayload
    });
    assert.equal(response.status, 503);
    assert.deepEqual(JSON.parse(response.body), { state: "unavailable" });
    assert.equal(calls.length, 1);
  }
});

test("CSRF query method content type body bounds and missing intent token fail before client", async () => {
  const cases = [
    { method: "GET", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE, headers: {} },
    { method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE + "?x=1", headers: {} },
    { method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
      headers: { origin: "https://foreign.example", "content-type": "application/json" }, body: proposalPayload },
    { method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
      headers: { origin: "https://social.example", "content-type": "text/plain" }, body: proposalPayload },
    { method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
      headers: { origin: "https://social.example", "content-type": "application/json" }, body: "x".repeat(8193) },
    { method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
      headers: { origin: "https://social.example", "content-type": "application/json" }, body: signedEventPayload }
  ];
  for (const candidate of cases) {
    const { bff, calls, cookie } = fixture();
    candidate.headers.cookie = cookie;
    const response = await bff(candidate);
    assert.notEqual(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { state: "unavailable" });
    assert.equal(calls.length, 0);
  }
});

test("malformed authorization result and conflicting UBID retry stay generic", async () => {
  const malformed = { ...result, subject };
  const { bff, cookie } = fixture({ authorizationValue: malformed });
  const response = await bff({
    method: "POST", url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
    headers: { cookie, origin: "https://social.example", "content-type": "application/json",
      "x-hodlxxi-device-binding-intent": intentToken },
    body: signedEventPayload
  });
  assert.equal(response.status, 503);
  assert.deepEqual(JSON.parse(response.body), { state: "unavailable" });
  assert.doesNotMatch(response.body, new RegExp(subject));
});

test("real BFF collapses every ambiguous authorization-client failure to the same 503", async () => {
  const cases = [
    ["upstream non-200", { authorizationFailure: new Error("upstream rejected") }],
    ["socket loss", { authorizationFailure: new Error("socket reset") }],
    ["timeout", { authorizationFailure: new Error("timeout") }],
    ["service-token failure", { authorizationFailure: new Error("token unavailable") }],
    ["response loss", { authorizationFailure: new Error("response closed") }],
    ["malformed response", { authorizationValue: { accepted: true } }]
  ];
  for (const [label, options] of cases) {
    const { bff, calls, cookie } = fixture(options);
    const response = await bff({
      method: "POST",
      url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE,
      headers: {
        cookie,
        origin: "https://social.example",
        "content-type": "application/json",
        "x-hodlxxi-device-binding-intent": intentToken
      },
      body: signedEventPayload
    });
    assert.equal(response.status, 503, label);
    assert.deepEqual(JSON.parse(response.body), { state: "unavailable" }, label);
    assert.equal(calls.filter(([kind]) => kind === "authorize").length, 1, label);
    assert.equal(calls.filter(([kind]) => kind === "intent").length, 0, label);
  }
});

test("enabled authorization blocks the legacy unsigned mutation path", async () => {
  const { bff, calls, cookie } = fixture();
  const response = await bff({
    method: "POST",
    url: SOCIAL_MESSAGING_DEVICE_BINDINGS_ROUTE,
    headers: { cookie, origin: "https://social.example", "content-type": "application/json" },
    body: proposalPayload
  });
  assert.equal(response.status, 503);
  assert.equal(calls.length, 0);
});

test("HTTP wrapper admits bounded bodies only on exact messaging mutation routes", async () => {
  for (const path of [
    SOCIAL_MESSAGING_DEVICE_BINDINGS_ROUTE,
    SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
    SOCIAL_MESSAGING_DEVICE_AUTHORIZATIONS_ROUTE
  ]) {
    const seen = [];
    const body = "{}";
    const incoming = {
      url: path,
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "2" },
      rawHeaders: ["Content-Type", "application/json", "Content-Length", "2"],
      async *[Symbol.asyncIterator]() { yield Buffer.from(body); }
    };
    const outgoing = {
      headers: {},
      setHeader(name, value) { this.headers[name] = value; },
      end(value) { this.body = value; }
    };
    await createHttpHandler({
      publicOrigin: "https://social.example",
      bff: async (request) => {
        seen.push(request);
        return { status: 200, headers: {}, body: "{}" };
      }
    })(incoming, outgoing);
    assert.equal(outgoing.statusCode, 200);
    assert.equal(seen[0].body, body);
  }

  let routed = 0;
  const incoming = {
    url: SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_INTENTS_ROUTE,
    method: "POST",
    headers: { "content-length": "8193" },
    rawHeaders: ["Content-Length", "8193"],
    async *[Symbol.asyncIterator]() { throw new Error("must not read"); }
  };
  const outgoing = {
    headers: {}, setHeader(name, value) { this.headers[name] = value; }, end(value) { this.body = value; }
  };
  await createHttpHandler({
    publicOrigin: "https://social.example",
    bff: async () => { routed += 1; }
  })(incoming, outgoing);
  assert.equal(outgoing.statusCode, 413);
  assert.equal(routed, 0);
});

const clientConfig = {
  enabled: true,
  socketPath: "/run/hodlxxi/ubid.sock",
  serviceTokenUrl: "https://identity.example/internal/v1/social/messaging/device-binding-authorization-service-token",
  authorizationIntentsUrl: "https://identity.example/internal/v1/social/messaging/device-binding-authorization-intents",
  authorizationsUrl: "https://identity.example/internal/v1/social/messaging/device-binding-authorizations",
  clientId: "social-device-authorization",
  clientSigningKeyId: "client-key",
  tokenEndpointAudience: "urn:authorization-token",
  signingKeyPath: "/run/credentials/social-device-authorization.pem",
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1000
};
const keyHandle = {
  async stat() { return { isFile: () => true, mode: 0o100600, size: 1024 }; },
  async readFile() { return "test-key"; },
  async close() {}
};

test("UBID client uses exact routes and forwards a locally expired exact submission to UBID", async () => {
  const calls = [];
  let clientNow = 1_788_906_599_000;
  const requestImpl = (options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.destroy = () => {};
    outgoing.setTimeout = () => outgoing;
    outgoing.end = (body) => {
      calls.push({ options, body });
      const incoming = new EventEmitter();
      incoming.destroy = () => {};
      incoming.statusCode = 200;
      incoming.headers = { "content-type": "application/json" };
      callback(incoming);
      queueMicrotask(() => {
        const value = options.path.endsWith("service-token")
          ? { access_token: "service-private-token", token_type: "Bearer", expires_in: 60,
              scope: "social:messaging-device-binding-authorization:manage" }
          : options.path.endsWith("authorization-intents") ? intent : result;
        incoming.emit("data", Buffer.from(canonicalMessagingDeviceJson(value)));
        incoming.emit("end");
      });
    };
    return outgoing;
  };
  const client = await createUbidMessagingDeviceAuthorizationClient(clientConfig, {
    requestImpl,
    openFileImpl: async () => keyHandle,
    createPrivateKeyImpl: () => ({ type: "private", asymmetricKeyType: "rsa",
      asymmetricKeyDetails: { modulusLength: 2048 } }),
    now: () => clientNow,
    random: () => Buffer.alloc(32, 7),
    signImpl: () => Buffer.from("signature"),
    cryptoImpl: webcrypto
  });
  assert.equal((await client.createIntentForViewer({
    viewerAccessToken, expectedSubject: subject, proposalPayload
  })).intentToken, intentToken);
  clientNow = 1_788_906_899_000;
  const received = await client.authorizeForViewer({
    viewerAccessToken, expectedSubject: subject, intentToken, signedEventPayload
  });
  assert.deepEqual(received, result);
  assert.deepEqual(calls.map((call) => call.options.path), [
    "/internal/v1/social/messaging/device-binding-authorization-service-token",
    "/internal/v1/social/messaging/device-binding-authorization-intents",
    "/internal/v1/social/messaging/device-binding-authorization-service-token",
    "/internal/v1/social/messaging/device-binding-authorizations"
  ]);
  const form = new URLSearchParams(calls[0].body);
  assert.equal(form.get("scope"), "social:messaging-device-binding-authorization:manage");
  assert.equal(calls[3].options.headers["X-HODLXXI-Device-Binding-Intent"], intentToken);
  const final = JSON.parse(calls[3].body);
  assert.deepEqual(final, { ...claim, digest, signature, signatureFormat: "nostr_event_id_bip340_v1" });
  assert.equal(Object.hasOwn(final, "intentToken"), false);
  assert.equal(Object.hasOwn(final, "signedEvent"), false);
});
