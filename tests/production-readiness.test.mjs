import test from "node:test";
import assert from "node:assert/strict";
import { constants } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  buildSocialProductionReadiness,
  PRODUCTION_READINESS_SCHEMA,
  REQUIRED_PRODUCT_ASSETS
} from "../src/server/social-production-readiness.mjs";

import {
  runProductionReadiness
} from "../scripts/hodlxxi-social-production-readiness.mjs";

const ROOT =
  fileURLToPath(new URL("../", import.meta.url));

const validEnv = () => ({
  SOCIAL_PUBLIC_ORIGIN: "https://social.example",
  HODLXXI_AUTHORITY_ORIGIN:
    "https://authority.example",
  HODLXXI_OAUTH_CLIENT_ID:
    "production-client-id",
  HODLXXI_OAUTH_CLIENT_SECRET:
    "SECRET-MUST-NEVER-APPEAR",
  SOCIAL_BIND_HOST: "127.0.0.1",
  SOCIAL_PORT: "5066",
  SOCIAL_TRANSACTION_TTL_SECONDS: "300",
  SOCIAL_SESSION_TTL_SECONDS: "1800",
  SOCIAL_MAX_PENDING_TRANSACTIONS: "64",
  SOCIAL_MAX_SESSIONS: "256",
  SOCIAL_OUTBOUND_TIMEOUT_MS: "5000",
  SOCIAL_NOSTR_RELAY_URL:
    "wss://relay.example",
  SOCIAL_NOSTR_PUBLISH_RELAY_URL:
    "wss://write.example"
});

const enabledPrivateFeaturesEnv = () => ({
  ...validEnv(),
  SOCIAL_FULL_DIRECTORY_ENABLED: "true",
  SOCIAL_RECIPIENT_CAPABILITY_ENABLED: "true",
  SOCIAL_UBID_PRIVATE_SOCKET_PATH:
    "/run/SECRET-full-directory.sock",
  SOCIAL_UBID_SERVICE_TOKEN_URL:
    "https://authority.example/internal/v1/social/service-token",
  SOCIAL_UBID_FULL_DIRECTORY_URL:
    "https://authority.example/internal/v1/social/full-directory",
  SOCIAL_UBID_SERVICE_CLIENT_ID:
    "SECRET-FULL-DIRECTORY-CLIENT",
  SOCIAL_UBID_SERVICE_CLIENT_SIGNING_KEY_ID:
    "SECRET-FULL-DIRECTORY-KID",
  SOCIAL_UBID_SERVICE_TOKEN_ENDPOINT_AUDIENCE:
    "SECRET-FULL-DIRECTORY-AUDIENCE",
  SOCIAL_UBID_SERVICE_SIGNING_KEY_PATH:
    "/etc/SECRET-full-directory-signing.pem",
  SOCIAL_UBID_SERVICE_TOKEN_TIMEOUT_MS:
    "5000",
  SOCIAL_UBID_FULL_DIRECTORY_TIMEOUT_MS:
    "5000"
});

test(
  "production readiness requires the complete current authenticated browser graph",
  () => {
    assert.deepEqual(
      REQUIRED_PRODUCT_ASSETS,
      [
        "web/index.html",
        "web/auth-entry.mjs",
        "web/auth-product.mjs",
        "web/authenticated-public-read.mjs",
        "web/authenticated-public-write.mjs",
        "web/nostr-event-verifier.mjs",
        "web/private-label-store.mjs",
        "web/secure-messaging-v128.mjs",
        "web/secure-messaging-v128.css",
        "web/components.mjs",
        "web/shell.mjs",
        "web/styles.css"
      ]
    );
  }
);

test(
  "valid base production configuration yields bounded non-secret source and configuration facts",
  async () => {
    const seen = [];

    const report =
      await buildSocialProductionReadiness(
        validEnv(),
        {
          cwd: ROOT,
          accessImpl: async (path, mode) => {
            seen.push({ path, mode });
          }
        }
      );

    assert.deepEqual(report, {
      schema: PRODUCTION_READINESS_SCHEMA,
      version: 1,
      ready: true,
      publicOrigin: "https://social.example",
      authorityOrigin:
        "https://authority.example",
      callbackUri:
        "https://social.example/auth/callback",
      bindHost: "127.0.0.1",
      port: 5066,
      healthPath: "/auth/health",
      staticEntrypoint: "web/index.html",
      authorityMode: "external-read-only",
      publicReadMode:
        "browser-one-shot-explicit-relay",
      relayHost: "relay.example",
      publicWriteMode:
        "browser-explicit-external-signer",
      publishRelayHost: "write.example",
      fullDirectoryMode: "disabled",
      recipientCapabilityMode: "disabled",
      privateLabelsMode:
        "source-browser-device-local",
      secureMessagingMode:
        "source-ui-shell-only-no-message-transport",
      serverSigning: false,
      keyCustody: false,
      hodlxxiWrites: false,
      sessionPersistence: "process-local",
      oauthCredentials:
        "configured-server-side",
      networkPerformed: false,
      listenerStarted: false,
      productionWrites: false
    });

    assert.equal(
      seen.length,
      REQUIRED_PRODUCT_ASSETS.length
    );

    assert.ok(
      seen.every(
        ({ mode }) => mode === constants.R_OK
      )
    );

    assert.doesNotMatch(
      JSON.stringify(report),
      /SECRET-MUST-NEVER-APPEAR|production-client-id/
    );
  }
);

test(
  "enabled private features are reported only as configuration/source modes without leaking integration secrets",
  async () => {
    const report =
      await buildSocialProductionReadiness(
        enabledPrivateFeaturesEnv(),
        {
          cwd: ROOT,
          accessImpl: async () => {}
        }
      );

    assert.equal(
      report.fullDirectoryMode,
      "configured-private-unix-socket-alias-only"
    );

    assert.equal(
      report.recipientCapabilityMode,
      "configured-process-local-opaque-direct-message-selection"
    );

    assert.equal(
      report.privateLabelsMode,
      "source-browser-device-local"
    );

    assert.equal(
      report.secureMessagingMode,
      "source-ui-shell-only-no-message-transport"
    );

    const encoded = JSON.stringify(report);

    for (const forbidden of [
      "SECRET-MUST-NEVER-APPEAR",
      "production-client-id",
      "SECRET-full-directory.sock",
      "SECRET-FULL-DIRECTORY-CLIENT",
      "SECRET-FULL-DIRECTORY-KID",
      "SECRET-FULL-DIRECTORY-AUDIENCE",
      "SECRET-full-directory-signing.pem"
    ]) {
      assert.doesNotMatch(
        encoded,
        new RegExp(forbidden)
      );
    }
  }
);

test(
  "rehearsal-style same-origin authority cannot pass production readiness",
  async () => {
    const env = validEnv();

    env.HODLXXI_AUTHORITY_ORIGIN =
      env.SOCIAL_PUBLIC_ORIGIN;

    let accesses = 0;

    await assert.rejects(
      buildSocialProductionReadiness(
        env,
        {
          cwd: ROOT,
          accessImpl: async () => {
            accesses += 1;
          }
        }
      ),
      /production readiness failed/
    );

    assert.equal(accesses, 0);
  }
);

test(
  "production readiness requires one explicit public read relay",
  async () => {
    const env = validEnv();

    delete env.SOCIAL_NOSTR_RELAY_URL;

    await assert.rejects(
      buildSocialProductionReadiness(
        env,
        {
          cwd: ROOT,
          accessImpl: async () => {}
        }
      ),
      /production readiness failed/
    );
  }
);

test(
  "production readiness requires a separate explicit publish relay",
  async () => {
    const env = validEnv();

    delete env.SOCIAL_NOSTR_PUBLISH_RELAY_URL;

    await assert.rejects(
      buildSocialProductionReadiness(
        env,
        {
          cwd: ROOT,
          accessImpl: async () => {}
        }
      ),
      /production readiness failed/
    );
  }
);

for (const missingAsset of [
  "web/private-label-store.mjs",
  "web/secure-messaging-v128.mjs",
  "web/secure-messaging-v128.css"
]) {
  test(
    `missing required authenticated asset ${missingAsset} fails closed`,
    async () => {
      let calls = 0;

      const missingCall =
        REQUIRED_PRODUCT_ASSETS.indexOf(
          missingAsset
        ) + 1;

      assert.ok(missingCall > 0);

      await assert.rejects(
        buildSocialProductionReadiness(
          validEnv(),
          {
            cwd: ROOT,
            accessImpl: async () => {
              calls += 1;

              if (calls === missingCall) {
                throw new Error(
                  "required asset unavailable"
                );
              }
            }
          }
        ),
        /production readiness failed/
      );

      assert.equal(calls, missingCall);
    }
  );
}

test(
  "recipient capability cannot be configured without Full Directory",
  async () => {
    const env = validEnv();

    env.SOCIAL_RECIPIENT_CAPABILITY_ENABLED =
      "true";

    let accesses = 0;

    await assert.rejects(
      buildSocialProductionReadiness(
        env,
        {
          cwd: ROOT,
          accessImpl: async () => {
            accesses += 1;
          }
        }
      ),
      /production readiness failed/
    );

    assert.equal(accesses, 0);
  }
);

test(
  "readiness runner emits JSON on success and one fixed diagnostic on failure",
  async () => {
    const output = [];
    const errors = [];

    const success =
      await runProductionReadiness({
        env: validEnv(),
        cwd: ROOT,
        accessImpl: async () => {},
        stdout: (value) => output.push(value),
        stderr: (value) => errors.push(value)
      });

    assert.equal(success, 0);
    assert.equal(errors.length, 0);
    assert.equal(output.length, 1);

    const report = JSON.parse(output[0]);

    assert.equal(report.ready, true);
    assert.equal(
      report.secureMessagingMode,
      "source-ui-shell-only-no-message-transport"
    );
    assert.equal(
      report.recipientCapabilityMode,
      "disabled"
    );
    assert.equal(
      report.networkPerformed,
      false
    );
    assert.equal(
      report.listenerStarted,
      false
    );

    assert.doesNotMatch(
      output[0],
      /SECRET-MUST-NEVER-APPEAR|production-client-id/
    );

    const failureOutput = [];
    const failureErrors = [];

    const failure =
      await runProductionReadiness({
        env: {},
        cwd: ROOT,
        accessImpl: async () => {},
        stdout: (value) =>
          failureOutput.push(value),
        stderr: (value) =>
          failureErrors.push(value)
      });

    assert.equal(failure, 2);
    assert.deepEqual(failureOutput, []);
    assert.deepEqual(
      failureErrors,
      ["production readiness failed"]
    );
  }
);

test(
  "readiness implementation has no network transport or listener path",
  async () => {
    const source = (
      await Promise.all([
        readFile(
          new URL(
            "../src/server/social-production-readiness.mjs",
            import.meta.url
          ),
          "utf8"
        ),
        readFile(
          new URL(
            "../scripts/hodlxxi-social-production-readiness.mjs",
            import.meta.url
          ),
          "utf8"
        )
      ])
    ).join("\n");

    assert.doesNotMatch(
      source,
      /globalThis\.fetch|fetch\s*\(|\.listen\s*\(|createServer|createHodlxxiOAuthClient/
    );

    assert.doesNotMatch(
      source,
      /console\.log\s*\([^)]*clientSecret|JSON\.stringify\s*\([^)]*clientSecret/
    );
  }
);
