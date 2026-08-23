import test from "node:test"; import assert from "node:assert/strict";
import { canonicalWssRelayUrl, parseSocialOAuthConfig } from "../src/server/social-oauth-config.mjs";
const valid = { publicOrigin:"https://social.example", authorityOrigin:"https://authority.example", clientId:"social", clientSecret:"test-secret", bindHost:"127.0.0.1", port:"8080", transactionTtlSeconds:"300", sessionTtlSeconds:"3600", maxPendingTransactions:"20", maxSessions:"20", outboundTimeoutMs:"1000" };
test("configuration is explicit, canonical, loopback, bounded, and derives callback", () => { const value=parseSocialOAuthConfig(valid); assert.equal(value.callbackUri,"https://social.example/auth/callback"); assert.equal(value.port,8080); });
test("configuration rejects non-origins, unsafe bind, missing values, and bad bounds without secret disclosure", () => { for (const patch of [{publicOrigin:"http://social.example"},{authorityOrigin:"https://u:p@authority.example"},{bindHost:"0.0.0.0"},{port:"0"},{clientSecret:""}]) assert.throws(()=>parseSocialOAuthConfig({...valid,...patch}), error=>!String(error).includes("test-secret")); });

test("authority timeout floor matches the existing HODLXXI authority probe", () => {
  assert.equal(
    parseSocialOAuthConfig({ ...valid, outboundTimeoutMs: "250" }).outboundTimeoutMs,
    250
  );
  for (const outboundTimeoutMs of ["100", "249"]) {
    assert.throws(() =>
      parseSocialOAuthConfig({ ...valid, outboundTimeoutMs })
    );
  }
});

test("Nostr public read relay is optional, explicit, canonical, and wss-only", () => {
  assert.equal(parseSocialOAuthConfig(valid).nostrRelayUrl, null);
  assert.equal(
    parseSocialOAuthConfig({
      ...valid,
      nostrRelayUrl: "wss://relay.example"
    }).nostrRelayUrl,
    "wss://relay.example/"
  );
  assert.equal(
    canonicalWssRelayUrl("wss://relay.example/path?scope=public"),
    "wss://relay.example/path?scope=public"
  );

  for (const nostrRelayUrl of [
    "ws://relay.example",
    "https://relay.example",
    "wss://user:pass@relay.example",
    "wss://relay.example/#fragment",
    "wss://relay.example./"
  ]) {
    assert.throws(() => parseSocialOAuthConfig({
      ...valid,
      nostrRelayUrl
    }));
  }
});

test("Nostr publish relay is separate optional explicit and wss-only", () => {
  assert.equal(parseSocialOAuthConfig(valid).nostrPublishRelayUrl, null);
  const configured = parseSocialOAuthConfig({
    ...valid,
    nostrRelayUrl: "wss://read.example",
    nostrPublishRelayUrl: "wss://write.example/path"
  });
  assert.equal(configured.nostrRelayUrl, "wss://read.example/");
  assert.equal(
    configured.nostrPublishRelayUrl,
    "wss://write.example/path"
  );

  for (const nostrPublishRelayUrl of [
    "ws://write.example",
    "https://write.example",
    "wss://user:pass@write.example",
    "wss://write.example/#fragment",
    "wss://write.example./"
  ]) {
    assert.throws(() => parseSocialOAuthConfig({
      ...valid,
      nostrPublishRelayUrl
    }));
  }
});
