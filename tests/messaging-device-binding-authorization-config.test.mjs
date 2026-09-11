import test from "node:test";
import assert from "node:assert/strict";
import {
  configFromEnvironment,
  parseSocialOAuthConfig
} from "../src/server/social-oauth-config.mjs";

const base = {
  publicOrigin: "https://social.example",
  authorityOrigin: "https://identity.example",
  clientId: "social",
  clientSecret: "secret",
  bindHost: "127.0.0.1",
  port: "8080",
  transactionTtlSeconds: "300",
  sessionTtlSeconds: "3600",
  maxPendingTransactions: "20",
  maxSessions: "20",
  outboundTimeoutMs: "1000"
};
const device = {
  messagingDeviceEnabled: "true",
  messagingDeviceSocketPath: "/run/hodlxxi/ubid.sock",
  messagingDeviceServiceTokenUrl: "https://identity.example/internal/v1/social/messaging/service-token",
  messagingDeviceBindingsUrl: "https://identity.example/internal/v1/social/messaging/device-bindings",
  messagingDeviceServiceClientId: "social-device",
  messagingDeviceServiceClientSigningKeyId: "device-key",
  messagingDeviceServiceTokenEndpointAudience: "urn:device-token",
  messagingDeviceSigningKeyPath: "/run/credentials/social-device.pem",
  messagingDeviceTokenTimeoutMs: "1000",
  messagingDeviceRequestTimeoutMs: "1000"
};
const authorization = {
  messagingDeviceAuthorizationEnabled: "true",
  messagingDeviceAuthorizationSocketPath: "/run/hodlxxi/ubid.sock",
  messagingDeviceAuthorizationServiceTokenUrl:
    "https://identity.example/internal/v1/social/messaging/device-binding-authorization-service-token",
  messagingDeviceAuthorizationIntentsUrl:
    "https://identity.example/internal/v1/social/messaging/device-binding-authorization-intents",
  messagingDeviceAuthorizationsUrl:
    "https://identity.example/internal/v1/social/messaging/device-binding-authorizations",
  messagingDeviceAuthorizationServiceClientId: "social-device-authorization",
  messagingDeviceAuthorizationServiceClientSigningKeyId: "authorization-key",
  messagingDeviceAuthorizationServiceTokenEndpointAudience: "urn:authorization-token",
  messagingDeviceAuthorizationSigningKeyPath: "/run/credentials/social-device-authorization.pem",
  messagingDeviceAuthorizationTokenTimeoutMs: "1000",
  messagingDeviceAuthorizationRequestTimeoutMs: "1500"
};

test("identity-authorized device binding is disabled by default", () => {
  assert.deepEqual(parseSocialOAuthConfig(base).messagingDeviceAuthorization, {
    enabled: false
  });
});

test("enabled identity authorization is complete and requires snapshot configuration", () => {
  assert.throws(
    () => parseSocialOAuthConfig({ ...base, ...authorization }),
    /invalid Social OAuth configuration/
  );
  const parsed = parseSocialOAuthConfig({ ...base, ...device, ...authorization });
  assert.deepEqual(parsed.messagingDeviceAuthorization, {
    enabled: true,
    socketPath: authorization.messagingDeviceAuthorizationSocketPath,
    serviceTokenUrl: authorization.messagingDeviceAuthorizationServiceTokenUrl,
    authorizationIntentsUrl: authorization.messagingDeviceAuthorizationIntentsUrl,
    authorizationsUrl: authorization.messagingDeviceAuthorizationsUrl,
    clientId: authorization.messagingDeviceAuthorizationServiceClientId,
    clientSigningKeyId: authorization.messagingDeviceAuthorizationServiceClientSigningKeyId,
    tokenEndpointAudience: authorization.messagingDeviceAuthorizationServiceTokenEndpointAudience,
    signingKeyPath: authorization.messagingDeviceAuthorizationSigningKeyPath,
    tokenTimeoutMs: 1000,
    requestTimeoutMs: 1500
  });
});

test("incomplete or noncanonical identity-authorization configuration fails closed", () => {
  for (const name of Object.keys(authorization).filter((name) => name !== "messagingDeviceAuthorizationEnabled")) {
    assert.throws(
      () => parseSocialOAuthConfig({ ...base, ...device, ...authorization, [name]: undefined }),
      /invalid Social OAuth configuration/,
      name
    );
  }
  for (const enabled of ["1", "yes", "TRUE", 1]) {
    assert.throws(() => parseSocialOAuthConfig({
      ...base,
      ...device,
      messagingDeviceAuthorizationEnabled: enabled
    }));
  }
});

test("environment mapping uses only the dedicated authorization variables", () => {
  const env = {
    SOCIAL_PUBLIC_ORIGIN: base.publicOrigin,
    HODLXXI_AUTHORITY_ORIGIN: base.authorityOrigin,
    HODLXXI_OAUTH_CLIENT_ID: base.clientId,
    HODLXXI_OAUTH_CLIENT_SECRET: base.clientSecret,
    SOCIAL_BIND_HOST: base.bindHost,
    SOCIAL_PORT: base.port,
    SOCIAL_TRANSACTION_TTL_SECONDS: base.transactionTtlSeconds,
    SOCIAL_SESSION_TTL_SECONDS: base.sessionTtlSeconds,
    SOCIAL_MAX_PENDING_TRANSACTIONS: base.maxPendingTransactions,
    SOCIAL_MAX_SESSIONS: base.maxSessions,
    SOCIAL_OUTBOUND_TIMEOUT_MS: base.outboundTimeoutMs,
    SOCIAL_MESSAGING_DEVICE_ENABLED: "true",
    SOCIAL_UBID_MESSAGING_PRIVATE_SOCKET_PATH: device.messagingDeviceSocketPath,
    SOCIAL_UBID_MESSAGING_SERVICE_TOKEN_URL: device.messagingDeviceServiceTokenUrl,
    SOCIAL_UBID_MESSAGING_DEVICE_BINDINGS_URL: device.messagingDeviceBindingsUrl,
    SOCIAL_UBID_MESSAGING_SERVICE_CLIENT_ID: device.messagingDeviceServiceClientId,
    SOCIAL_UBID_MESSAGING_SERVICE_CLIENT_SIGNING_KEY_ID: device.messagingDeviceServiceClientSigningKeyId,
    SOCIAL_UBID_MESSAGING_SERVICE_TOKEN_ENDPOINT_AUDIENCE: device.messagingDeviceServiceTokenEndpointAudience,
    SOCIAL_UBID_MESSAGING_SERVICE_SIGNING_KEY_PATH: device.messagingDeviceSigningKeyPath,
    SOCIAL_UBID_MESSAGING_SERVICE_TOKEN_TIMEOUT_MS: device.messagingDeviceTokenTimeoutMs,
    SOCIAL_UBID_MESSAGING_DEVICE_TIMEOUT_MS: device.messagingDeviceRequestTimeoutMs,
    SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_ENABLED: "true",
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_PRIVATE_SOCKET_PATH: authorization.messagingDeviceAuthorizationSocketPath,
    SOCIAL_UBID_MESSAGING_DEVICE_BINDING_AUTHORIZATION_SERVICE_TOKEN_URL: authorization.messagingDeviceAuthorizationServiceTokenUrl,
    SOCIAL_UBID_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTENTS_URL: authorization.messagingDeviceAuthorizationIntentsUrl,
    SOCIAL_UBID_MESSAGING_DEVICE_BINDING_AUTHORIZATIONS_URL: authorization.messagingDeviceAuthorizationsUrl,
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_SERVICE_CLIENT_ID: authorization.messagingDeviceAuthorizationServiceClientId,
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_SERVICE_CLIENT_SIGNING_KEY_ID: authorization.messagingDeviceAuthorizationServiceClientSigningKeyId,
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_SERVICE_TOKEN_ENDPOINT_AUDIENCE: authorization.messagingDeviceAuthorizationServiceTokenEndpointAudience,
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_SERVICE_SIGNING_KEY_PATH: authorization.messagingDeviceAuthorizationSigningKeyPath,
    SOCIAL_UBID_MESSAGING_AUTHORIZATION_SERVICE_TOKEN_TIMEOUT_MS: authorization.messagingDeviceAuthorizationTokenTimeoutMs,
    SOCIAL_UBID_MESSAGING_DEVICE_BINDING_AUTHORIZATION_TIMEOUT_MS: authorization.messagingDeviceAuthorizationRequestTimeoutMs
  };
  assert.equal(
    configFromEnvironment(env).messagingDeviceAuthorization.authorizationsUrl,
    authorization.messagingDeviceAuthorizationsUrl
  );
});
