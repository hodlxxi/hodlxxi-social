import assert from "node:assert/strict";
import {
  createHash
} from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
  MESSAGING_RECIPIENT_SCOPE,
  UBID_MESSAGING_RECIPIENT_DEVICES_PATH,
  UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH,
  createUbidMessagingRecipientClient,
  normalizeMessagingRecipientPackage
} from "../src/server/ubid-messaging-recipient-client.mjs";

const recipientAlias =
  "p_KHcJHzAgVKtH830W3gJGIg";

const viewerToken =
  "viewer-oauth-private-token";

const serviceToken =
  "service-private-token";

const clientConfig =
  Object.freeze({
    enabled: true,
    socketPath:
      "/run/hodlxxi/ubid-messaging-recipient.sock",
    serviceTokenUrl:
      "https://hodlxxi.example/internal/v1/social/messaging/recipient-service-token",
    recipientDevicesUrl:
      "https://hodlxxi.example/internal/v1/social/messaging/recipient-devices",
    clientId:
      "social-messaging-recipient-v1",
    clientSigningKeyId:
      "kid-recipient-1",
    tokenEndpointAudience:
      "urn:test:messaging-recipient-token",
    signingKeyPath:
      "/run/hodlxxi/social-messaging-recipient-client.pem",
    tokenTimeoutMs: 1000,
    requestTimeoutMs: 1000
  });

const device = Object.freeze({
  deviceHandle:
    "d_KHcJHzAgVKtH830W3gJGIg",
  algorithm:
    "x25519-v1",
  version: 1,
  publicKey:
    "09" + "00".repeat(31),
  validFrom: 1000,
  expiresAt: 5000
});

const packageFor = (
  {
    alias = recipientAlias,
    devices = [device],
    issuedAt = 2000,
    expiresAt = 4000
  } = {}
) => {
  const sortedDevices =
    [...devices]
      .sort(
        (left, right) =>
          left.deviceHandle.localeCompare(
            right.deviceHandle
          )
      )
      .map(
        (item) => ({
          algorithm:
            item.algorithm,
          deviceHandle:
            item.deviceHandle,
          expiresAt:
            item.expiresAt,
          publicKey:
            item.publicKey,
          validFrom:
            item.validFrom,
          version:
            item.version
        })
      );

  const evidence = {
    alias,
    complete: true,
    devices: sortedDevices,
    expiresAt,
    issuedAt,
    schema:
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
    source: "hodlxxi-ubid",
    version: 1
  };

  const snapshotId =
    "sha256:" +
    createHash("sha256")
      .update(
        JSON.stringify(evidence),
        "ascii"
      )
      .digest("hex");

  return {
    schema:
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
    version: 1,
    source: "hodlxxi-ubid",
    snapshotId,
    complete: true,
    alias,
    issuedAt,
    expiresAt,
    devices
  };
};

const privateKeyHandle = (
  mode = 0o100600
) => ({
  async stat() {
    return {
      isFile: () => true,
      mode,
      size: 1700
    };
  },
  async readFile() {
    return "test-private-key";
  },
  async close() {}
});

const requestHarness = ({
  packageResponse =
    packageFor(),
  packageSource,
  recipientStatus = 200
} = {}) => {
  const calls = [];

  const requestImpl = (
    options,
    callback
  ) => {
    const outgoing =
      new EventEmitter();

    outgoing.destroy = () => {};
    outgoing.setTimeout =
      () => outgoing;

    outgoing.end = (body) => {
      calls.push({
        options,
        body
      });

      const incoming =
        new EventEmitter();

      incoming.destroy = () => {};
      incoming.statusCode =
        options.path ===
        UBID_MESSAGING_RECIPIENT_DEVICES_PATH
          ? recipientStatus
          : 200;
      incoming.headers = {
        "content-type":
          "application/json"
      };

      callback(incoming);

      queueMicrotask(() => {
        const source =
          options.path ===
          UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH
            ? JSON.stringify({
                access_token:
                  serviceToken,
                token_type:
                  "Bearer",
                expires_in: 60,
                scope:
                  MESSAGING_RECIPIENT_SCOPE
              })
            : packageSource ??
              JSON.stringify(
                packageResponse
              );

        incoming.emit(
          "data",
          Buffer.from(
            source,
            "utf8"
          )
        );
        incoming.emit("end");
      });
    };

    return outgoing;
  };

  return {
    calls,
    requestImpl
  };
};

const createClientForTest = async (
  harness,
  {
    keyMode = 0o100600,
    config = clientConfig
  } = {}
) =>
  createUbidMessagingRecipientClient(
    config,
    {
      requestImpl:
        harness.requestImpl,
      openFileImpl:
        async () =>
          privateKeyHandle(
            keyMode
          ),
      createPrivateKeyImpl:
        () => ({
          type: "private",
          asymmetricKeyType: "rsa",
          asymmetricKeyDetails: {
            modulusLength: 2048
          }
        }),
      now:
        () =>
          1_700_000_000_000,
      random:
        () =>
          Buffer.alloc(32, 7),
      signImpl:
        () =>
          Buffer.from(
            "test-signature"
          )
    }
  );

test(
  "recipient client freezes exact scope paths and package schema",
  () => {
    assert.equal(
      MESSAGING_RECIPIENT_SCOPE,
      "social:messaging-recipient:read"
    );

    assert.equal(
      UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH,
      "/internal/v1/social/messaging/recipient-service-token"
    );

    assert.equal(
      UBID_MESSAGING_RECIPIENT_DEVICES_PATH,
      "/internal/v1/social/messaging/recipient-devices"
    );

    assert.equal(
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
      "hodlxxi.social_messaging_recipient_package.v1"
    );
  }
);

test(
  "recipient package normalization accepts only the exact alias-bound closed package",
  () => {
    const normalized =
      normalizeMessagingRecipientPackage(
        packageFor(),
        {
          expectedAlias:
            recipientAlias
        }
      );

    assert.equal(
      normalized.alias,
      recipientAlias
    );

    assert.equal(
      normalized.devices.length,
      1
    );

    assert.equal(
      normalized.devices[0]
        .deviceHandle,
      device.deviceHandle
    );

    assert.ok(
      Object.isFrozen(
        normalized
      )
    );

    assert.ok(
      Object.isFrozen(
        normalized.devices
      )
    );

    assert.deepEqual(
      Object.keys(
        normalized
      ),
      [
        "schema",
        "version",
        "source",
        "snapshotId",
        "complete",
        "alias",
        "issuedAt",
        "expiresAt",
        "devices"
      ]
    );
  }
);

test(
  "recipient package normalization rejects alias mismatch raw target fields duplicate devices and changed snapshot evidence",
  () => {
    const bad = [
      {
        ...packageFor(),
        alias:
          "p_o8YlA6r_0WQmPpOfJp4aXA"
      },
      {
        ...packageFor(),
        targetSubject:
          "a".repeat(64)
      },
      packageFor({
        devices: [
          device,
          { ...device }
        ]
      }),
      {
        ...packageFor(),
        issuedAt: 2001
      },
      packageFor({
        devices: [
          {
            ...device,
            publicKey:
              "00".repeat(32)
          }
        ]
      })
    ];

    for (const value of bad) {
      assert.throws(
        () =>
          normalizeMessagingRecipientPackage(
            value,
            {
              expectedAlias:
                recipientAlias
            }
          ),
        {
          message:
            "messaging_recipient_unavailable"
        }
      );
    }
  }
);

test(
  "recipient client uses only Unix socket transport and keeps service and viewer credentials separate",
  async () => {
    const harness =
      requestHarness();

    const client =
      await createClientForTest(
        harness
      );

    const received =
      await client.resolveForViewer({
        viewerAccessToken:
          viewerToken,
        recipientAlias
      });

    assert.equal(
      harness.calls.length,
      2
    );

    const [
      tokenCall,
      recipientCall
    ] = harness.calls;

    assert.equal(
      tokenCall.options.socketPath,
      clientConfig.socketPath
    );
    assert.equal(
      tokenCall.options.path,
      UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH
    );
    assert.equal(
      tokenCall.options.method,
      "POST"
    );
    assert.equal(
      tokenCall.options.hostname,
      undefined
    );
    assert.equal(
      tokenCall.options.host,
      undefined
    );
    assert.equal(
      tokenCall.options.port,
      undefined
    );
    assert.equal(
      tokenCall.options.headers
        .Authorization,
      undefined
    );
    assert.equal(
      tokenCall.body.includes(
        viewerToken
      ),
      false
    );

    const form =
      new URLSearchParams(
        tokenCall.body
      );

    assert.equal(
      form.get("scope"),
      MESSAGING_RECIPIENT_SCOPE
    );

    assert.equal(
      form.get("grant_type"),
      "client_credentials"
    );

    assert.equal(
      form.get("client_id"),
      clientConfig.clientId
    );

    assert.ok(
      form.get(
        "client_assertion"
      )
    );

    assert.equal(
      recipientCall.options
        .socketPath,
      clientConfig.socketPath
    );

    assert.equal(
      recipientCall.options.path,
      UBID_MESSAGING_RECIPIENT_DEVICES_PATH
    );

    assert.equal(
      recipientCall.options.method,
      "POST"
    );

    assert.equal(
      recipientCall.options.hostname,
      undefined
    );

    assert.equal(
      recipientCall.options.port,
      undefined
    );

    assert.equal(
      recipientCall.options.headers
        .Authorization,
      `Bearer ${serviceToken}`
    );

    assert.equal(
      recipientCall.options.headers[
        "X-HODLXXI-Viewer-Authorization"
      ],
      `Bearer ${viewerToken}`
    );

    assert.equal(
      recipientCall.options.headers[
        "Content-Type"
      ],
      "application/json"
    );

    assert.equal(
      recipientCall.body,
      JSON.stringify({
        recipientAlias
      })
    );

    assert.equal(
      received.alias,
      recipientAlias
    );

    const serialized =
      JSON.stringify(received);

    assert.equal(
      serialized.includes(
        viewerToken
      ),
      false
    );

    assert.equal(
      serialized.includes(
        serviceToken
      ),
      false
    );

    assert.equal(
      serialized.includes(
        "targetSubject"
      ),
      false
    );

    assert.equal(
      serialized.includes(
        "deviceId"
      ),
      false
    );

    assert.equal(
      serialized.includes(
        "bindingId"
      ),
      false
    );
  }
);

test(
  "recipient client never accepts an rc capability as recipient input",
  async () => {
    const harness =
      requestHarness();

    const client =
      await createClientForTest(
        harness
      );

    await assert.rejects(
      client.resolveForViewer({
        viewerAccessToken:
          viewerToken,
        recipientAlias:
          `rc_${"C".repeat(43)}`
      }),
      {
        message:
          "messaging_recipient_unavailable"
      }
    );

    assert.equal(
      harness.calls.length,
      0
    );
  }
);

test(
  "recipient client collapses target-side non-200 responses without returning target state",
  async () => {
    for (const status of [
      400,
      401,
      403,
      404,
      503
    ]) {
      const harness =
        requestHarness({
          recipientStatus:
            status
        });

      const client =
        await createClientForTest(
          harness
        );

      await assert.rejects(
        client.resolveForViewer({
          viewerAccessToken:
            viewerToken,
          recipientAlias
        }),
        {
          message:
            "messaging_recipient_unavailable"
        }
      );
    }
  }
);

test(
  "recipient client rejects duplicate JSON members and malformed upstream projection",
  async () => {
    const valid =
      packageFor();

    const duplicateSource =
      JSON.stringify(valid)
        .replace(
          `"alias":"${recipientAlias}"`,
          `"alias":"${recipientAlias}","alias":"${recipientAlias}"`
        );

    const harness =
      requestHarness({
        packageSource:
          duplicateSource
      });

    const client =
      await createClientForTest(
        harness
      );

    await assert.rejects(
      client.resolveForViewer({
        viewerAccessToken:
          viewerToken,
        recipientAlias
      }),
      {
        message:
          "messaging_recipient_unavailable"
      }
    );
  }
);

test(
  "recipient client rejects permissive signing-key mode before any request",
  async () => {
    const harness =
      requestHarness();

    await assert.rejects(
      createClientForTest(
        harness,
        {
          keyMode:
            0o100644
        }
      ),
      {
        message:
          "messaging_recipient_unavailable"
      }
    );

    assert.equal(
      harness.calls.length,
      0
    );
  }
);

test(
  "recipient client rejects unsafe socket paths and endpoint path substitution before key loading",
  async () => {
    for (const config of [
      {
        ...clientConfig,
        socketPath:
          "relative/private.sock"
      },
      {
        ...clientConfig,
        recipientDevicesUrl:
          "https://hodlxxi.example/internal/v1/social/messaging/device-bindings"
      },
      {
        ...clientConfig,
        serviceTokenUrl:
          "https://hodlxxi.example/internal/v1/social/messaging/service-token"
      }
    ]) {
      const harness =
        requestHarness();

      await assert.rejects(
        createClientForTest(
          harness,
          { config }
        ),
        {
          message:
            "messaging_recipient_unavailable"
        }
      );

      assert.equal(
        harness.calls.length,
        0
      );
    }
  }
);

test(
  "recipient client rejects a service token equal to the human viewer bearer",
  async () => {
    const calls = [];

    const requestImpl = (
      options,
      callback
    ) => {
      const outgoing =
        new EventEmitter();

      outgoing.destroy = () => {};
      outgoing.setTimeout =
        () => outgoing;

      outgoing.end = (body) => {
        calls.push({
          options,
          body
        });

        const incoming =
          new EventEmitter();

        incoming.destroy = () => {};
        incoming.statusCode = 200;
        incoming.headers = {
          "content-type":
            "application/json"
        };

        callback(incoming);

        queueMicrotask(() => {
          incoming.emit(
            "data",
            Buffer.from(
              JSON.stringify({
                access_token:
                  viewerToken,
                token_type:
                  "Bearer",
                expires_in: 60,
                scope:
                  MESSAGING_RECIPIENT_SCOPE
              })
            )
          );
          incoming.emit(
            "end"
          );
        });
      };

      return outgoing;
    };

    const client =
      await createUbidMessagingRecipientClient(
        clientConfig,
        {
          requestImpl,
          openFileImpl:
            async () =>
              privateKeyHandle(),
          createPrivateKeyImpl:
            () => ({
              type: "private",
              asymmetricKeyType:
                "rsa",
              asymmetricKeyDetails: {
                modulusLength: 2048
              }
            }),
          now:
            () =>
              1_700_000_000_000,
          random:
            () =>
              Buffer.alloc(
                32,
                7
              ),
          signImpl:
            () =>
              Buffer.from(
                "test-signature"
              )
        }
      );

    await assert.rejects(
      client.resolveForViewer({
        viewerAccessToken:
          viewerToken,
        recipientAlias
      }),
      {
        message:
          "messaging_recipient_unavailable"
      }
    );

    assert.equal(
      calls.length,
      1
    );
  }
);
