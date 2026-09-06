import assert from "node:assert/strict";
import test from "node:test";

import {
  configFromEnvironment,
  parseSocialOAuthConfig
} from "../src/server/social-oauth-config.mjs";

import {
  createMessagingRecipientIntegration
} from "../scripts/hodlxxi-social-server.mjs";

const base = Object.freeze({
  publicOrigin: "https://social.example",
  authorityOrigin: "https://authority.example",
  clientId: "social",
  clientSecret: "test-secret",
  bindHost: "127.0.0.1",
  port: "5067",
  transactionTtlSeconds: "300",
  sessionTtlSeconds: "3600",
  maxPendingTransactions: "20",
  maxSessions: "20",
  outboundTimeoutMs: "1000"
});

const fullDirectory = Object.freeze({
  fullDirectoryEnabled: "true",
  fullDirectorySocketPath:
    "/run/hodlxxi/ubid-social-private.sock",
  fullDirectoryServiceTokenUrl:
    "https://ubid.internal.example/internal/v1/social/service-token",
  fullDirectoryUrl:
    "https://ubid.internal.example/internal/v1/social/full-directory",
  fullDirectoryServiceClientId:
    "social-confidential-backend",
  fullDirectoryServiceClientSigningKeyId:
    "full-directory-kid-1",
  fullDirectoryServiceTokenEndpointAudience:
    "https://ubid.internal.example/internal/v1/social/service-token",
  fullDirectorySigningKeyPath:
    "/run/credentials/hodlxxi-social/full-directory.pem",
  fullDirectoryTokenTimeoutMs: "1000",
  fullDirectoryRequestTimeoutMs: "1500"
});

const recipient = Object.freeze({
  recipientCapabilityEnabled: "true",
  messagingRecipientEnabled: "true",
  messagingRecipientSocketPath:
    "/run/hodlxxi/ubid-messaging-private.sock",
  messagingRecipientServiceTokenUrl:
    "https://ubid.internal.example/internal/v1/social/messaging/recipient-service-token",
  messagingRecipientDevicesUrl:
    "https://ubid.internal.example/internal/v1/social/messaging/recipient-devices",
  messagingRecipientServiceClientId:
    "social-messaging-recipient-v1",
  messagingRecipientServiceClientSigningKeyId:
    "recipient-kid-1",
  messagingRecipientServiceTokenEndpointAudience:
    "https://ubid.internal.example/internal/v1/social/messaging/recipient-service-token",
  messagingRecipientSigningKeyPath:
    "/run/credentials/hodlxxi-social/messaging-recipient.pem",
  messagingRecipientTokenTimeoutMs: "1000",
  messagingRecipientRequestTimeoutMs: "1250"
});

const expectedRecipient = Object.freeze({
  enabled: true,
  socketPath:
    recipient.messagingRecipientSocketPath,
  serviceTokenUrl:
    recipient.messagingRecipientServiceTokenUrl,
  recipientDevicesUrl:
    recipient.messagingRecipientDevicesUrl,
  clientId:
    recipient.messagingRecipientServiceClientId,
  clientSigningKeyId:
    recipient.messagingRecipientServiceClientSigningKeyId,
  tokenEndpointAudience:
    recipient.messagingRecipientServiceTokenEndpointAudience,
  signingKeyPath:
    recipient.messagingRecipientSigningKeyPath,
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1250
});

test(
  "messaging recipient runtime is disabled by default without inspecting dormant fields",
  () => {
    const input = { ...base };
    let inspections = 0;

    Object.defineProperty(
      input,
      "messagingRecipientSocketPath",
      {
        enumerable: true,
        get() {
          inspections += 1;
          throw new Error(
            "disabled recipient runtime must stay dormant"
          );
        }
      }
    );

    assert.deepEqual(
      parseSocialOAuthConfig(input)
        .messagingRecipient,
      { enabled: false }
    );

    assert.equal(inspections, 0);
  }
);

test(
  "messaging recipient runtime requires recipient capability and parses an exact independent client",
  () => {
    assert.throws(
      () =>
        parseSocialOAuthConfig({
          ...base,
          ...recipient,
          recipientCapabilityEnabled: "false"
        }),
      /invalid Social OAuth configuration/
    );

    const parsed =
      parseSocialOAuthConfig({
        ...base,
        ...fullDirectory,
        ...recipient
      });

    assert.deepEqual(
      parsed.messagingRecipient,
      expectedRecipient
    );

    assert.notEqual(
      parsed.messagingRecipient.clientId,
      parsed.fullDirectory.clientId
    );
  }
);

test(
  "enabled messaging recipient runtime fails closed on unsafe or incomplete configuration",
  () => {
    for (const patch of [
      {
        messagingRecipientSocketPath:
          "relative.sock"
      },
      {
        messagingRecipientServiceTokenUrl:
          "http://ubid.internal.example/internal/v1/social/messaging/recipient-service-token"
      },
      {
        messagingRecipientDevicesUrl:
          undefined
      },
      {
        messagingRecipientServiceClientId:
          ""
      },
      {
        messagingRecipientServiceClientSigningKeyId:
          ""
      },
      {
        messagingRecipientServiceTokenEndpointAudience:
          " unsafe"
      },
      {
        messagingRecipientSigningKeyPath:
          "relative.pem"
      },
      {
        messagingRecipientTokenTimeoutMs:
          "249"
      },
      {
        messagingRecipientRequestTimeoutMs:
          "30001"
      }
    ]) {
      assert.throws(
        () =>
          parseSocialOAuthConfig({
            ...base,
            ...fullDirectory,
            ...recipient,
            ...patch
          }),
        /invalid Social OAuth configuration/
      );
    }

    for (const messagingRecipientEnabled of [
      "1",
      "TRUE",
      "yes",
      1
    ]) {
      assert.throws(
        () =>
          parseSocialOAuthConfig({
            ...base,
            ...fullDirectory,
            ...recipient,
            messagingRecipientEnabled
          }),
        /invalid Social OAuth configuration/
      );
    }
  }
);

test(
  "environment mapping keeps recipient authority separate while reusing only the private messaging socket transport",
  () => {
    const parsed =
      configFromEnvironment({
        SOCIAL_PUBLIC_ORIGIN:
          base.publicOrigin,
        HODLXXI_AUTHORITY_ORIGIN:
          base.authorityOrigin,
        HODLXXI_OAUTH_CLIENT_ID:
          base.clientId,
        HODLXXI_OAUTH_CLIENT_SECRET:
          base.clientSecret,
        SOCIAL_BIND_HOST:
          base.bindHost,
        SOCIAL_PORT:
          base.port,
        SOCIAL_TRANSACTION_TTL_SECONDS:
          base.transactionTtlSeconds,
        SOCIAL_SESSION_TTL_SECONDS:
          base.sessionTtlSeconds,
        SOCIAL_MAX_PENDING_TRANSACTIONS:
          base.maxPendingTransactions,
        SOCIAL_MAX_SESSIONS:
          base.maxSessions,
        SOCIAL_OUTBOUND_TIMEOUT_MS:
          base.outboundTimeoutMs,

        SOCIAL_FULL_DIRECTORY_ENABLED:
          "true",
        SOCIAL_RECIPIENT_CAPABILITY_ENABLED:
          "true",
        SOCIAL_UBID_PRIVATE_SOCKET_PATH:
          fullDirectory.fullDirectorySocketPath,
        SOCIAL_UBID_SERVICE_TOKEN_URL:
          fullDirectory.fullDirectoryServiceTokenUrl,
        SOCIAL_UBID_FULL_DIRECTORY_URL:
          fullDirectory.fullDirectoryUrl,
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
          fullDirectory.fullDirectoryRequestTimeoutMs,

        SOCIAL_MESSAGING_RECIPIENT_ENABLED:
          "true",
        SOCIAL_UBID_MESSAGING_PRIVATE_SOCKET_PATH:
          recipient.messagingRecipientSocketPath,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_URL:
          recipient.messagingRecipientServiceTokenUrl,
        SOCIAL_UBID_MESSAGING_RECIPIENT_DEVICES_URL:
          recipient.messagingRecipientDevicesUrl,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_CLIENT_ID:
          recipient.messagingRecipientServiceClientId,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_CLIENT_SIGNING_KEY_ID:
          recipient.messagingRecipientServiceClientSigningKeyId,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_ENDPOINT_AUDIENCE:
          recipient.messagingRecipientServiceTokenEndpointAudience,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_SIGNING_KEY_PATH:
          recipient.messagingRecipientSigningKeyPath,
        SOCIAL_UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_TIMEOUT_MS:
          recipient.messagingRecipientTokenTimeoutMs,
        SOCIAL_UBID_MESSAGING_RECIPIENT_TIMEOUT_MS:
          recipient.messagingRecipientRequestTimeoutMs
      });

    assert.deepEqual(
      parsed.messagingRecipient,
      expectedRecipient
    );

    assert.equal(
      parsed.messagingRecipient.socketPath,
      recipient.messagingRecipientSocketPath
    );

    assert.equal(
      Object.hasOwn(
        parsed.messagingRecipient,
        "deviceBindingsUrl"
      ),
      false
    );
  }
);

test(
  "disabled messaging recipient composition creates no client",
  async () => {
    let calls = 0;

    const result =
      await createMessagingRecipientIntegration(
        { enabled: false },
        {
          clientFactory() {
            calls += 1;
            throw new Error(
              "must not create disabled client"
            );
          }
        }
      );

    assert.equal(result, undefined);
    assert.equal(calls, 0);
  }
);

test(
  "enabled messaging recipient composition injects the exact dedicated configuration",
  async () => {
    const client = Object.freeze({
      resolveForViewer() {}
    });

    let seen;

    const result =
      await createMessagingRecipientIntegration(
        expectedRecipient,
        {
          clientFactory(input) {
            seen = input;
            return client;
          }
        }
      );

    assert.equal(seen, expectedRecipient);
    assert.equal(result, client);
  }
);
