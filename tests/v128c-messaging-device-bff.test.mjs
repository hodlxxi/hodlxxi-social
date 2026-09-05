import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { EventEmitter } from "node:events";

import {
  parseSocialOAuthConfig
} from "../src/server/social-oauth-config.mjs";

import {
  createSocialOAuthBff
} from "../src/server/social-oauth-bff.mjs";

import {
  createBoundedStore
} from "../src/server/social-oauth-memory.mjs";

import {
  SESSION_COOKIE_NAME
} from "../src/server/social-oauth-cookie.mjs";

import {
  createHttpHandler
} from "../scripts/hodlxxi-social-server.mjs";

import {
  createUbidMessagingDeviceClient
} from "../src/server/ubid-messaging-device-client.mjs";

const subject = "a".repeat(64);
const viewerToken =
  "viewer-oauth-private-token";

const snapshot = Object.freeze({
  schema:
    "hodlxxi.social_messaging_device_binding_snapshot.v1",
  version: 1,
  source: "hodlxxi-ubid",
  snapshotId:
    "sha256:" + "1".repeat(64),
  complete: true,
  issuedAt: 1000,
  expiresAt: 2000,
  activeDevices: Object.freeze([])
});

const result = Object.freeze({
  schema:
    "hodlxxi.social_messaging_device_binding_result.v1",
  version: 1,
  operation: "register",
  device: Object.freeze({
    deviceId: "2".repeat(64),
    bindingId: "3".repeat(64),
    algorithm: "x25519-v1",
    version: 1,
    publicKey: "4".repeat(64),
    validFrom:
      "2026-09-04T09:00:00Z",
    expiresAt:
      "2026-10-04T09:00:00Z"
  })
});

const baseConfig = {
  publicOrigin: "https://social.example",
  authorityOrigin:
    "https://authority.example",
  clientId: "social-client",
  clientSecret: "secret",
  bindHost: "127.0.0.1",
  port: "5067",
  transactionTtlSeconds: "300",
  sessionTtlSeconds: "3600",
  maxPendingTransactions: "10",
  maxSessions: "10",
  outboundTimeoutMs: "1000"
};

test(
  "messaging device config is disabled by default and strictly parsed when enabled",
  () => {
    const disabled =
      parseSocialOAuthConfig(
        baseConfig
      );

    assert.deepEqual(
      disabled.messagingDevice,
      { enabled: false }
    );

    const enabled =
      parseSocialOAuthConfig({
        ...baseConfig,
        messagingDeviceEnabled:
          "true",
        messagingDeviceSocketPath:
          "/run/private/social.sock",
        messagingDeviceServiceTokenUrl:
          "https://hodlxxi.example/internal/v1/social/messaging/service-token",
        messagingDeviceBindingsUrl:
          "https://hodlxxi.example/internal/v1/social/messaging/device-bindings",
        messagingDeviceServiceClientId:
          "social-messaging-v1",
        messagingDeviceServiceClientSigningKeyId:
          "kid-1",
        messagingDeviceServiceTokenEndpointAudience:
          "urn:test:messaging-token",
        messagingDeviceSigningKeyPath:
          "/run/private/client.pem",
        messagingDeviceTokenTimeoutMs:
          "1000",
        messagingDeviceRequestTimeoutMs:
          "1000"
      });

    assert.equal(
      enabled.messagingDevice.enabled,
      true
    );

    assert.equal(
      enabled.messagingDevice.clientId,
      "social-messaging-v1"
    );
  }
);

const fixture = (
  authorityStatus = "full"
) => {
  const pendingTransactions =
    createBoundedStore({
      ttlSeconds: 300,
      capacity: 10,
      now: () => 0
    });

  const sessions =
    createBoundedStore({
      ttlSeconds: 3600,
      capacity: 10,
      now: () => 0
    });

  const sessionId = "session-v128c";

  assert.equal(
    sessions.create(
      sessionId,
      {
        subject,
        viewerAccessToken:
          viewerToken
      }
    ),
    true
  );

  const calls = [];

  const messagingDeviceClient = {
    async currentForViewer(input) {
      calls.push([
        "get",
        input
      ]);

      return snapshot;
    },

    async applyForViewer(input) {
      calls.push([
        "post",
        input
      ]);

      return result;
    }
  };

  const config = {
    ...baseConfig,
    callbackUri:
      "https://social.example/auth/callback",
    scope: "openid",
    transactionTtlSeconds: 300,
    sessionTtlSeconds: 3600,
    messagingDevice: {
      enabled: true
    }
  };

  const bff =
    createSocialOAuthBff({
      config,
      pendingTransactions,
      sessions,
      oauthClient: {},
      authorityReader:
        async (candidate) => ({
          subject: candidate,
          status:
            authorityStatus,
          valid: true
        }),
      messagingDeviceClient
    });

  return {
    bff,
    calls,
    cookie:
      `${SESSION_COOKIE_NAME}=${sessionId}`
  };
};

test(
  "Full session can read only its own messaging-device projection",
  async () => {
    const { bff, calls, cookie } =
      fixture();

    const response =
      await bff({
        method: "GET",
        url:
          "/auth/messaging-device-bindings",
        headers: {
          cookie
        }
      });

    assert.equal(
      response.status,
      200
    );

    assert.deepEqual(
      JSON.parse(response.body),
      snapshot
    );

    assert.deepEqual(
      calls,
      [
        [
          "get",
          {
            viewerAccessToken:
              viewerToken
          }
        ]
      ]
    );

    assert.doesNotMatch(
      response.body,
      /viewer-oauth|Bearer|subject/i
    );
  }
);

test(
  "Limited session cannot reach messaging device client",
  async () => {
    const { bff, calls, cookie } =
      fixture("limited");

    const response =
      await bff({
        method: "GET",
        url:
          "/auth/messaging-device-bindings",
        headers: {
          cookie
        }
      });

    assert.equal(
      response.status,
      403
    );

    assert.equal(
      calls.length,
      0
    );
  }
);

test(
  "POST requires same-origin and forwards only command bytes plus server-side viewer token",
  async () => {
    const { bff, calls, cookie } =
      fixture();

    const commandPayload =
      JSON.stringify({
        schema:
          "hodlxxi.social_messaging_device_binding_command.v1",
        version: 1,
        operation: "register",
        deviceId: "2".repeat(64),
        algorithm: "x25519-v1",
        publicKey: "11".repeat(32),
        expectedBindingId: null,
        requestId: "5".repeat(64)
      });

    const denied =
      await bff({
        method: "POST",
        url:
          "/auth/messaging-device-bindings",
        headers: {
          cookie,
          origin:
            "https://foreign.example",
          "content-type":
            "application/json"
        },
        body: commandPayload
      });

    assert.equal(
      denied.status,
      403
    );

    assert.equal(
      calls.length,
      0
    );

    const accepted =
      await bff({
        method: "POST",
        url:
          "/auth/messaging-device-bindings",
        headers: {
          cookie,
          origin:
            "https://social.example",
          "content-type":
            "application/json"
        },
        body: commandPayload
      });

    assert.equal(
      accepted.status,
      200
    );

    assert.deepEqual(
      calls,
      [
        [
          "post",
          {
            viewerAccessToken:
              viewerToken,
            commandPayload
          }
        ]
      ]
    );

    assert.doesNotMatch(
      accepted.body,
      /viewer-oauth|Bearer|subject/i
    );
  }
);

const request = (
  port,
  {
    path,
    method,
    body
  }
) =>
  new Promise(
    (resolve, reject) => {
      const req =
        http.request(
          {
            host: "127.0.0.1",
            port,
            path,
            method,
            headers:
              body === undefined
                ? {}
                : {
                    "Content-Type":
                      "application/json",
                    "Content-Length":
                      String(
                        Buffer.byteLength(
                          body
                        )
                      )
                  }
          },
          (res) => {
            const chunks = [];

            res.on(
              "data",
              (chunk) =>
                chunks.push(chunk)
            );

            res.once(
              "end",
              () =>
                resolve({
                  status:
                    res.statusCode,
                  body:
                    Buffer.concat(
                      chunks
                    ).toString()
                })
            );
          }
        );

      req.once("error", reject);
      req.end(body);
    }
  );

test(
  "HTTP wrapper allows bounded body only on messaging-device POST",
  async () => {
    const seen = [];

    const server =
      http.createServer(
        createHttpHandler({
          publicOrigin:
            "https://social.example",
          bff:
            async (incoming) => {
              seen.push(incoming);

              return {
                status: 200,
                headers: {},
                body: "{}"
              };
            }
        })
      );

    await new Promise(
      (resolve, reject) => {
        server.once(
          "error",
          reject
        );

        server.listen(
          0,
          "127.0.0.1",
          resolve
        );
      }
    );

    try {
      const address =
        server.address();

      const good =
        await request(
          address.port,
          {
            path:
              "/auth/messaging-device-bindings",
            method: "POST",
            body: "{}"
          }
        );

      assert.equal(
        good.status,
        200
      );

      assert.equal(
        seen.length,
        1
      );

      assert.equal(
        seen[0].body,
        "{}"
      );

      const blocked =
        await request(
          address.port,
          {
            path: "/auth/logout",
            method: "POST",
            body: "{}"
          }
        );

      assert.equal(
        blocked.status,
        413
      );

      assert.equal(
        seen.length,
        1
      );
    } finally {
      await new Promise(
        (resolve) =>
          server.close(resolve)
      );
    }
  }
);

const messagingClientConfig = Object.freeze({
  enabled: true,
  socketPath: "/run/hodlxxi/ubid-messaging.sock",
  serviceTokenUrl:
    "https://hodlxxi.example/internal/v1/social/messaging/service-token",
  deviceBindingsUrl:
    "https://hodlxxi.example/internal/v1/social/messaging/device-bindings",
  clientId: "social-messaging-v1",
  clientSigningKeyId: "kid-1",
  tokenEndpointAudience:
    "https://hodlxxi.example/internal/v1/social/messaging/service-token",
  signingKeyPath: "/run/hodlxxi/social-messaging-client.pem",
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1000
});

const serviceToken = "service-private-token";

const privateKeyHandle = (mode = 0o100600) => ({
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

const messagingRequestHarness = ({
  deviceResponse = snapshot,
  deviceSource
} = {}) => {
  const calls = [];

  const requestImpl = (options, callback) => {
    const outgoing = new EventEmitter();

    outgoing.destroy = () => {};
    outgoing.setTimeout = () => outgoing;

    outgoing.end = (body) => {
      calls.push({
        options,
        body
      });

      const incoming = new EventEmitter();
      incoming.destroy = () => {};
      incoming.statusCode = 200;
      incoming.headers = {
        "content-type": "application/json"
      };

      callback(incoming);

      queueMicrotask(() => {
        const source =
          options.path ===
          "/internal/v1/social/messaging/service-token"
            ? JSON.stringify({
                access_token: serviceToken,
                token_type: "Bearer",
                expires_in: 60,
                scope:
                  "social:messaging-device:manage"
              })
            : deviceSource ??
              JSON.stringify(deviceResponse);

        incoming.emit(
          "data",
          Buffer.from(source, "utf8")
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

const createMessagingClientForTest = async (
  harness,
  {
    keyMode = 0o100600
  } = {}
) =>
  createUbidMessagingDeviceClient(
    messagingClientConfig,
    {
      requestImpl: harness.requestImpl,
      openFileImpl: async () =>
        privateKeyHandle(keyMode),
      createPrivateKeyImpl: () => ({
        type: "private",
        asymmetricKeyType: "rsa",
        asymmetricKeyDetails: {
          modulusLength: 2048
        }
      }),
      now: () => 1_700_000_000_000,
      random: () => Buffer.alloc(32, 7),
      signImpl: () =>
        Buffer.from("test-signature")
    }
  );

test(
  "messaging device client keeps service and viewer credentials separated",
  async () => {
    const harness =
      messagingRequestHarness();

    const client =
      await createMessagingClientForTest(
        harness
      );

    const received =
      await client.currentForViewer({
        viewerAccessToken: viewerToken
      });

    assert.deepEqual(received, snapshot);
    assert.equal(harness.calls.length, 2);

    const [tokenCall, deviceCall] =
      harness.calls;

    assert.equal(
      tokenCall.options.socketPath,
      messagingClientConfig.socketPath
    );
    assert.equal(
      tokenCall.options.path,
      "/internal/v1/social/messaging/service-token"
    );
    assert.equal(
      tokenCall.options.method,
      "POST"
    );
    assert.equal(
      tokenCall.options.headers.Authorization,
      undefined
    );
    assert.equal(
      tokenCall.body.includes(viewerToken),
      false
    );

    const form =
      new URLSearchParams(tokenCall.body);

    assert.equal(
      form.get("grant_type"),
      "client_credentials"
    );
    assert.equal(
      form.get("client_id"),
      messagingClientConfig.clientId
    );
    assert.equal(
      form.get("scope"),
      "social:messaging-device:manage"
    );
    assert.equal(
      form.get("client_assertion_type"),
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    assert.ok(
      form.get("client_assertion")
    );

    assert.equal(
      deviceCall.options.path,
      "/internal/v1/social/messaging/device-bindings"
    );
    assert.equal(
      deviceCall.options.method,
      "GET"
    );
    assert.equal(
      deviceCall.options.headers.Authorization,
      `Bearer ${serviceToken}`
    );
    assert.equal(
      deviceCall.options.headers[
        "X-HODLXXI-Viewer-Authorization"
      ],
      `Bearer ${viewerToken}`
    );
    assert.equal(deviceCall.body, undefined);

    const projected =
      JSON.stringify(received);

    assert.equal(
      projected.includes(viewerToken),
      false
    );
    assert.equal(
      projected.includes(serviceToken),
      false
    );
    assert.equal(
      projected.includes(subject),
      false
    );
  }
);

test(
  "messaging device client preserves exact command bytes on private POST",
  async () => {
    const harness =
      messagingRequestHarness({
        deviceResponse: result
      });

    const client =
      await createMessagingClientForTest(
        harness
      );

    const commandPayload =
      JSON.stringify({
        schema:
          "hodlxxi.social_messaging_device_binding_command.v1",
        version: 1,
        operation: "register",
        deviceId: "2".repeat(64),
        algorithm: "x25519-v1",
        publicKey: "11".repeat(32),
        expectedBindingId: null,
        requestId: "5".repeat(64)
      });

    const received =
      await client.applyForViewer({
        viewerAccessToken: viewerToken,
        commandPayload
      });

    assert.deepEqual(received, result);
    assert.equal(harness.calls.length, 2);

    const deviceCall = harness.calls[1];

    assert.equal(
      deviceCall.options.path,
      "/internal/v1/social/messaging/device-bindings"
   );
    assert.equal(
      deviceCall.options.method,
      "POST"
    );
    assert.equal(
      deviceCall.options.headers.Authorization,
      `Bearer ${serviceToken}`
   );
    assert.equal(
      deviceCall.options.headers[
        "X-HODLXXI-Viewer-Authorization"
      ],
      `Bearer ${viewerToken}`
   );
    assert.equal(
      deviceCall.options.headers[
        "Content-Type"
      ],
      "application/json"
    );
    assert.equal(
      deviceCall.options.headers[
        "Content-Length"
      ],
      String(
        Buffer.byteLength(
          commandPayload,
          "utf8"
        )
      )
    );
    assert.equal(
      deviceCall.body,
      commandPayload
    );
  }
);

test(
  "messaging device client rejects subject-bearing or non-exact UBID projection",
  async () => {
    const injected =
      JSON.stringify({
        ...snapshot,
        subject
      });

    const harness =
      messagingRequestHarness({
        deviceSource: injected
      });

    const client =
      await createMessagingClientForTest(
        harness
      );

    await assert.rejects(
      client.currentForViewer({
        viewerAccessToken: viewerToken
      }),
      /messaging_device_unavailable/
    );
  }
);

test(
  "messaging device client rejects permissive service signing-key mode before network use",
  async () => {
    const harness =
      messagingRequestHarness();

    await assert.rejects(
      createMessagingClientForTest(
        harness,
        {
          keyMode: 0o100644
        }
      ),
      /messaging_device_unavailable/
    );

    assert.equal(
      harness.calls.length,
      0
    );
  }
);
