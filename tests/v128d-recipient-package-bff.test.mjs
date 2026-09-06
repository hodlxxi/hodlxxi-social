import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  createSocialOAuthBff,
  SOCIAL_MESSAGING_RECIPIENT_PACKAGE_ROUTE
} from "../src/server/social-oauth-bff.mjs";

import {
  createBoundedStore
} from "../src/server/social-oauth-memory.mjs";

import {
  SESSION_COOKIE_NAME
} from "../src/server/social-oauth-cookie.mjs";

const subject = "a".repeat(64);
const sessionId = "D".repeat(43);
const viewerAccessToken = "viewer-private-oauth-token";
const capability = `rc_${"C".repeat(43)}`;
const recipientAlias = "p_KHcJHzAgVKtH830W3gJGIg";
const deviceHandle = `d_${"A".repeat(22)}`;
const publicKey = "09" + "00".repeat(31);

const canonicalJson = (value) => {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  if (
    value !== null &&
    typeof value === "object"
  ) {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalJson(value[key])}`
      )
      .join(",")}}`;
  }

  return JSON.stringify(value);
};

const packageFor = (alias = recipientAlias) => {
  const evidence = {
    schema:
      "hodlxxi.social_messaging_recipient_package.v1",
    version: 1,
    source: "hodlxxi-ubid",
    alias,
    complete: true,
    issuedAt: 1000,
    expiresAt: 2000,
    devices: [
      {
        deviceHandle,
        algorithm: "x25519-v1",
        version: 1,
        publicKey,
        validFrom: 900,
        expiresAt: 3000
      }
    ]
  };

  return Object.freeze({
    ...evidence,
    snapshotId:
      "sha256:" +
      createHash("sha256")
        .update(
          canonicalJson(evidence),
          "ascii"
        )
        .digest("hex")
  });
};

const fixture = ({
  withSession = true,
  capabilityResult = {
    state: "available",
    alias: recipientAlias
  },
  packageResult = packageFor(),
  includeResolver = true,
  includeRecipientClient = true
} = {}) => {
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

  if (withSession) {
    assert.equal(
      sessions.create(
        sessionId,
        {
          subject,
          viewerAccessToken
        }
      ),
      true
    );
  }

  const seen = {
    resolver: [],
    recipient: []
  };

  const recipientCapabilityIssuer = {
    issue() {
      throw new Error(
        "issuance not used by package route"
      );
    },
    ...(includeResolver
      ? {
          async resolve(input) {
            seen.resolver.push(input);

            if (
              capabilityResult instanceof Error
            ) {
              throw capabilityResult;
            }

            return capabilityResult;
          }
        }
      : {})
  };

  const messagingRecipientClient =
    includeRecipientClient
      ? {
          async resolveForViewer(input) {
            seen.recipient.push(input);

            if (
              packageResult instanceof Error
            ) {
              throw packageResult;
            }

            return packageResult;
          }
        }
      : undefined;

  const bff =
    createSocialOAuthBff({
      config: {
        publicOrigin:
          "https://social.example"
      },
      pendingTransactions,
      sessions,
      oauthClient: {},
      recipientCapabilityIssuer,
      messagingRecipientClient
    });

  return {
    bff,
    seen,
    cookie:
      `${SESSION_COOKIE_NAME}=${sessionId}`
  };
};

const request = (
  cookie,
  {
    method = "POST",
    origin = "https://social.example",
    selectedCapability = capability,
    url =
      SOCIAL_MESSAGING_RECIPIENT_PACKAGE_ROUTE
  } = {}
) => ({
  method,
  url,
  headers: {
    ...(cookie ? { cookie } : {}),
    ...(origin ? { origin } : {}),
    ...(selectedCapability
      ? {
          "x-hodlxxi-recipient-capability":
            selectedCapability
        }
      : {})
  }
});

test(
  "bodyless same-origin package route resolves rc locally then sends only viewer bearer plus p alias to recipient client",
  async () => {
    const {
      bff,
      seen,
      cookie
    } = fixture();

    const response =
      await bff(
        request(cookie)
      );

    assert.equal(
      response.status,
      200
    );

    assert.deepEqual(
      seen.resolver,
      [
        {
          sessionId,
          capability
        }
      ]
    );

    assert.deepEqual(
      seen.recipient,
      [
        {
          viewerAccessToken,
          recipientAlias
        }
      ]
    );

    const body =
      JSON.parse(response.body);

    assert.equal(
      body.alias,
      recipientAlias
    );

    assert.equal(
      body.devices[0].deviceHandle,
      deviceHandle
    );

    assert.equal(
      body.devices[0].publicKey,
      publicKey
    );

    assert.doesNotMatch(
      response.body,
      /rc_|viewer-private-oauth-token|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|deviceId|bindingId|xpub|npub|nprofile/i
    );
  }
);

test(
  "cross-origin package redemption is denied before resolver and UBID client",
  async () => {
    const {
      bff,
      seen,
      cookie
    } = fixture();

    const response =
      await bff(
        request(
          cookie,
          {
            origin:
              "https://foreign.example"
          }
        )
      );

    assert.equal(
      response.status,
      403
    );

    assert.deepEqual(
      seen,
      {
        resolver: [],
        recipient: []
      }
    );
  }
);

test(
  "unauthenticated package redemption is denied before capability lookup",
  async () => {
    const {
      bff,
      seen
    } = fixture({
      withSession: false
    });

    const response =
      await bff(
        request(undefined)
      );

    assert.equal(
      response.status,
      401
    );

    assert.equal(
      seen.resolver.length,
      0
    );

    assert.equal(
      seen.recipient.length,
      0
    );
  }
);

test(
  "malformed capability is a safe 400 and never reaches resolver or UBID",
  async () => {
    const {
      bff,
      seen,
      cookie
    } = fixture();

    const response =
      await bff(
        request(
          cookie,
          {
            selectedCapability:
              "rc_invalid"
          }
        )
      );

    assert.equal(
      response.status,
      400
    );

    assert.equal(
      seen.resolver.length,
      0
    );

    assert.equal(
      seen.recipient.length,
      0
    );

    assert.deepEqual(
      JSON.parse(response.body),
      { state: "unavailable" }
    );
  }
);

test(
  "missing resolver or recipient client is generic unavailable without target-state detail",
  async () => {
    for (const options of [
      {
        includeResolver: false
      },
      {
        includeRecipientClient: false
      }
    ]) {
      const {
        bff,
        cookie
      } = fixture(options);

      const response =
        await bff(
          request(cookie)
        );

      assert.equal(
        response.status,
        503
      );

      assert.deepEqual(
        JSON.parse(response.body),
        { state: "unavailable" }
      );
    }
  }
);

test(
  "stale denied or malformed capability resolution collapses to one generic 503",
  async () => {
    for (const capabilityResult of [
      { state: "unavailable" },
      new Error("synthetic resolver failure"),
      {
        state: "available",
        alias: "p_wrong"
      }
    ]) {
      const {
        bff,
        seen,
        cookie
      } = fixture({
        capabilityResult
      });

      const response =
        await bff(
          request(cookie)
        );

      assert.equal(
        response.status,
        503
      );

      assert.deepEqual(
        JSON.parse(response.body),
        { state: "unavailable" }
      );

      assert.equal(
        seen.recipient.length,
        0
      );
    }
  }
);

test(
  "recipient client failure or malformed package collapses to generic 503",
  async () => {
    for (const packageResult of [
      new Error("synthetic UBID failure"),
      {
        ...packageFor(),
        alias:
          "p_o8YlA6r_0WQmPpOfJp4aXA"
      },
      {
        ...packageFor(),
        deviceId:
          "2".repeat(64)
      }
    ]) {
      const {
        bff,
        cookie
      } = fixture({
        packageResult
      });

      const response =
        await bff(
          request(cookie)
        );

      assert.equal(
        response.status,
        503
      );

      assert.deepEqual(
        JSON.parse(response.body),
        { state: "unavailable" }
      );
    }
  }
);

test(
  "recipient package route is POST-only and query-free",
  async () => {
    const {
      bff,
      seen,
      cookie
    } = fixture();

    const wrongMethod =
      await bff(
        request(
          cookie,
          {
            method: "GET"
          }
        )
      );

    assert.equal(
      wrongMethod.status,
      405
    );

    const query =
      await bff(
        request(
          cookie,
          {
            url:
              `${SOCIAL_MESSAGING_RECIPIENT_PACKAGE_ROUTE}?x=1`
          }
        )
      );

    assert.equal(
      query.status,
      400
    );

    assert.equal(
      seen.resolver.length,
      0
    );

    assert.equal(
      seen.recipient.length,
      0
    );
  }
);
