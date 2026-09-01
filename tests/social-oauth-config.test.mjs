import test from "node:test"; import assert from "node:assert/strict";
import { canonicalHttpsUrl, canonicalWssRelayUrl, configFromEnvironment, parseSocialOAuthConfig } from "../src/server/social-oauth-config.mjs";
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

const fullDirectory = {
  fullDirectoryEnabled: "true",
  fullDirectoryServiceTokenUrl:
    "https://ubid.internal.example/internal/v1/social/service-token",
  fullDirectoryUrl:
    "https://ubid.internal.example/internal/v1/social/full-directory",
  fullDirectoryServiceClientId: "social-confidential-backend",
  fullDirectoryServiceClientSigningKeyId: "social-client-key-1",
  fullDirectoryServiceTokenEndpointAudience:
    "https://ubid.internal.example/internal/v1/social/service-token",
  fullDirectorySigningKeyPath:
    "/run/credentials/hodlxxi-social/full-directory.pem",
  fullDirectoryTokenTimeoutMs: "1000",
  fullDirectoryRequestTimeoutMs: "1500"
};

test("Full directory client is disabled by default and exact when enabled", () => {
  assert.deepEqual(parseSocialOAuthConfig(valid).fullDirectory, {
    enabled: false
  });
  assert.deepEqual(
    parseSocialOAuthConfig({ ...valid, ...fullDirectory }).fullDirectory,
    {
      enabled: true,
      serviceTokenUrl: fullDirectory.fullDirectoryServiceTokenUrl,
      directoryUrl: fullDirectory.fullDirectoryUrl,
      clientId: "social-confidential-backend",
      clientSigningKeyId: "social-client-key-1",
      tokenEndpointAudience:
        fullDirectory.fullDirectoryServiceTokenEndpointAudience,
      signingKeyPath: fullDirectory.fullDirectorySigningKeyPath,
      tokenTimeoutMs: 1000,
      requestTimeoutMs: 1500
    }
  );
  assert.equal(
    canonicalHttpsUrl(
      "https://ubid.internal.example/internal/v1/social/full-directory"
    ),
    "https://ubid.internal.example/internal/v1/social/full-directory"
  );
});

test("enabled Full directory configuration fails closed when incomplete or unsafe", () => {
  for (const patch of [
    { fullDirectoryServiceTokenUrl: undefined },
    { fullDirectoryUrl: "http://ubid.internal.example/directory" },
    { fullDirectoryServiceClientId: "" },
    { fullDirectoryServiceClientSigningKeyId: "" },
    { fullDirectoryServiceClientSigningKeyId: "x".repeat(256) },
    { fullDirectoryServiceTokenEndpointAudience: "" },
    { fullDirectoryServiceTokenEndpointAudience: " unsafe" },
    { fullDirectoryServiceTokenEndpointAudience: "unsafe\u0000audience" },
    { fullDirectorySigningKeyPath: "relative.pem" },
    { fullDirectoryTokenTimeoutMs: "249" },
    { fullDirectoryRequestTimeoutMs: "30001" }
  ]) {
    assert.throws(
      () => parseSocialOAuthConfig({
        ...valid,
        ...fullDirectory,
        ...patch
      }),
      /invalid Social OAuth configuration/
    );
  }
  for (const fullDirectoryEnabled of ["1", "TRUE", "yes"]) {
    assert.throws(() => parseSocialOAuthConfig({
      ...valid,
      fullDirectoryEnabled
    }));
  }
});

test("Full directory token audience is an exact credential string, not an endpoint URL", () => {
  for (const tokenEndpointAudience of [
    "https://ubid.internal.example/internal/v1/social/service-token",
    "urn:hodlxxi:ubid:confidential-service-token"
  ]) {
    const parsed = parseSocialOAuthConfig({
      ...valid,
      ...fullDirectory,
      fullDirectoryServiceTokenEndpointAudience: tokenEndpointAudience
    });
    assert.equal(
      parsed.fullDirectory.tokenEndpointAudience,
      tokenEndpointAudience
    );
  }
});

test("environment mapping uses only exact UBID client-credential names", () => {
  const parsed = configFromEnvironment({
    SOCIAL_PUBLIC_ORIGIN: valid.publicOrigin,
    HODLXXI_AUTHORITY_ORIGIN: valid.authorityOrigin,
    HODLXXI_OAUTH_CLIENT_ID: valid.clientId,
    HODLXXI_OAUTH_CLIENT_SECRET: valid.clientSecret,
    SOCIAL_BIND_HOST: valid.bindHost,
    SOCIAL_PORT: valid.port,
    SOCIAL_TRANSACTION_TTL_SECONDS: valid.transactionTtlSeconds,
    SOCIAL_SESSION_TTL_SECONDS: valid.sessionTtlSeconds,
    SOCIAL_MAX_PENDING_TRANSACTIONS: valid.maxPendingTransactions,
    SOCIAL_MAX_SESSIONS: valid.maxSessions,
    SOCIAL_OUTBOUND_TIMEOUT_MS: valid.outboundTimeoutMs,
    SOCIAL_FULL_DIRECTORY_ENABLED: "true",
    SOCIAL_UBID_SERVICE_TOKEN_URL:
      fullDirectory.fullDirectoryServiceTokenUrl,
    SOCIAL_UBID_FULL_DIRECTORY_URL: fullDirectory.fullDirectoryUrl,
    SOCIAL_UBID_SERVICE_CLIENT_ID:
      fullDirectory.fullDirectoryServiceClientId,
    SOCIAL_UBID_SERVICE_CLIENT_SIGNING_KEY_ID:
      fullDirectory.fullDirectoryServiceClientSigningKeyId,
    SOCIAL_UBID_SERVICE_TOKEN_ENDPOINT_AUDIENCE:
      fullDirectory.fullDirectoryServiceTokenEndpointAudience,
    SOCIAL_UBID_SERVICE_SIGNING_KEY_PATH:
      fullDirectory.fullDirectorySigningKeyPath,
    SOCIAL_UBID_SERVICE_TOKEN_TIMEOUT_MS:
      fullDirectory.fullDirectoryTokenTimeoutMs,
    SOCIAL_UBID_FULL_DIRECTORY_TIMEOUT_MS:
      fullDirectory.fullDirectoryRequestTimeoutMs
  });
  assert.equal(
    parsed.fullDirectory.clientSigningKeyId,
    "social-client-key-1"
  );
  assert.equal(
    parsed.fullDirectory.tokenEndpointAudience,
    fullDirectory.fullDirectoryServiceTokenEndpointAudience
  );
  assert.equal(Object.hasOwn(parsed.fullDirectory, "issuer"), false);
  assert.equal(Object.hasOwn(parsed.fullDirectory, "principal"), false);
});
