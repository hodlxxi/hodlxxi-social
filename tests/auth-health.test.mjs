import test from "node:test";
import assert from "node:assert/strict";

import { parseSocialOAuthConfig } from "../src/server/social-oauth-config.mjs";
import { createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs";

const config = parseSocialOAuthConfig({
  publicOrigin: "https://social.example",
  authorityOrigin: "https://authority.example",
  clientId: "health-test-client",
  clientSecret: "health-test-secret",
  bindHost: "127.0.0.1",
  port: 5066,
  transactionTtlSeconds: 300,
  sessionTtlSeconds: 1800,
  maxPendingTransactions: 8,
  maxSessions: 8,
  outboundTimeoutMs: 1000
});

const makeBff = () => {
  let oauthCalls = 0;
  let authorityCalls = 0;

  const bff = createSocialOAuthBff({
    config,
    pendingTransactions: createBoundedStore({
      ttlSeconds: 300,
      capacity: 8
    }),
    sessions: createBoundedStore({
      ttlSeconds: 1800,
      capacity: 8
    }),
    oauthClient: Object.freeze({
      async authenticate() {
        oauthCalls += 1;
        throw new Error("must not authenticate");
      }
    }),
    authorityReader: async () => {
      authorityCalls += 1;
      throw new Error("must not read authority");
    },
    random: (size) => Buffer.alloc(size, 0x31)
  });

  return {
    bff,
    calls: () => ({ oauthCalls, authorityCalls })
  };
};

test("health is exact fixed no-store liveness with zero OAuth or authority reads", async () => {
  const { bff, calls } = makeBff();

  const result = await bff({
    method: "GET",
    url: "/auth/health",
    headers: {}
  });

  assert.equal(result.status, 200);
  assert.equal(result.body, '{"ok":true}');
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.equal(
    result.headers["Content-Type"],
    "application/json; charset=utf-8"
  );
  assert.deepEqual(calls(), {
    oauthCalls: 0,
    authorityCalls: 0
  });
});

test("health rejects query parameters and non-GET methods without side effects", async () => {
  const { bff, calls } = makeBff();

  const query = await bff({
    method: "GET",
    url: "/auth/health?subject=hostile",
    headers: {}
  });

  const post = await bff({
    method: "POST",
    url: "/auth/health",
    headers: {}
  });

  assert.equal(query.status, 400);
  assert.equal(post.status, 405);
  assert.deepEqual(JSON.parse(query.body), {
    error: "request_rejected"
  });
  assert.deepEqual(JSON.parse(post.body), {
    error: "request_rejected"
  });
  assert.deepEqual(calls(), {
    oauthCalls: 0,
    authorityCalls: 0
  });
});

test("health does not depend on or parse a browser session cookie", async () => {
  const { bff, calls } = makeBff();

  const result = await bff({
    method: "GET",
    url: "/auth/health",
    headers: {
      cookie: "malformed cookie that session routes reject"
    }
  });

  assert.equal(result.status, 200);
  assert.equal(result.body, '{"ok":true}');
  assert.deepEqual(calls(), {
    oauthCalls: 0,
    authorityCalls: 0
  });
});
