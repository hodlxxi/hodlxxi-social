import test from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  verify
} from "node:crypto";

import {
  CLIENT_ASSERTION_LIFETIME_SECONDS,
  CLIENT_ASSERTION_TYPE,
  createUbidFullDirectoryClient,
  FULL_DIRECTORY_SCOPE,
  normalizeUbidFullDirectory,
  validateServiceTokenResponse
} from "../src/server/ubid-full-directory-client.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048
});
const privatePem = privateKey.export({
  type: "pkcs8",
  format: "pem"
});

const config = Object.freeze({
  enabled: true,
  serviceTokenUrl: "https://ubid.internal.example/internal/v1/social/service-token",
  directoryUrl: "https://ubid.internal.example/internal/v1/social/full-directory",
  clientId: "hodlxxi-social",
  principal: "social-service",
  issuer: "hodlxxi-social-service-client",
  audience: "https://ubid.internal.example/internal/v1/social/service-token",
  purpose: "social-full-directory",
  tokenUse: "client-assertion",
  signingKeyPath: "/run/credentials/hodlxxi-social/full-directory.pem",
  expectedSchema: "hodlxxi.social.full_directory.v1",
  expectedVersion: 1,
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1500
});

const reply = (value, status = 200) => new Response(
  JSON.stringify(value),
  {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  }
);

const tokenDocument = (patch = {}) => ({
  access_token: "request-scoped-service-bearer",
  token_type: "Bearer",
  expires_in: 60,
  scope: FULL_DIRECTORY_SCOPE,
  ...patch
});

const directoryDocument = (participants = [
  {
    alias: "member~4N8x",
    identity_class: "full",
    current_full_relation_satisfied: true
  }
]) => ({
  schema: config.expectedSchema,
  version: config.expectedVersion,
  participants
});

const dependencies = (fetchImpl, overrides = {}) => ({
  fetchImpl,
  readFileImpl: async (path, encoding) => {
    assert.equal(path, config.signingKeyPath);
    assert.equal(encoding, "utf8");
    return privatePem;
  },
  now: () => 1_800_000_000_000,
  setTimeoutImpl: () => 1,
  clearTimeoutImpl() {},
  ...overrides
});

const decode = (part) => JSON.parse(Buffer.from(part, "base64url"));

test("fresh RS256 assertion carries exact short-lived service claims", async () => {
  const calls = [];
  let entropy = 0x31;
  const client = await createUbidFullDirectoryClient(
    config,
    dependencies(async (url, init) => {
      calls.push({ url, init });
      return calls.length % 2 === 1
        ? reply(tokenDocument())
        : reply(directoryDocument());
    }, {
      random: (size) => Buffer.alloc(size, entropy++)
    })
  );

  await client.readForViewer({ viewerAccessToken: "human-bearer-private" });
  await client.readForViewer({ viewerAccessToken: "human-bearer-private" });

  const assertions = [calls[0], calls[2]].map(({ init }) =>
    new URLSearchParams(init.body).get("client_assertion")
  );
  assert.notEqual(assertions[0], assertions[1]);

  for (const assertion of assertions) {
    const [encodedHeader, encodedClaims, encodedSignature] =
      assertion.split(".");
    assert.deepEqual(decode(encodedHeader), {
      alg: "RS256",
      typ: "JWT"
    });
    const claims = decode(encodedClaims);
    assert.deepEqual(
      {
        iss: claims.iss,
        sub: claims.sub,
        aud: claims.aud,
        client_id: claims.client_id,
        purpose: claims.purpose,
        token_use: claims.token_use
      },
      {
        iss: config.issuer,
        sub: config.principal,
        aud: config.audience,
        client_id: config.clientId,
        purpose: config.purpose,
        token_use: config.tokenUse
      }
    );
    assert.equal(
      claims.exp - claims.iat,
      CLIENT_ASSERTION_LIFETIME_SECONDS
    );
    assert.match(claims.jti, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(
      verify(
        "RSA-SHA256",
        Buffer.from(`${encodedHeader}.${encodedClaims}`, "ascii"),
        publicKey,
        Buffer.from(encodedSignature, "base64url")
      ),
      true
    );
  }
});

test("service token and human viewer credentials remain structurally separate", async () => {
  const calls = [];
  const client = await createUbidFullDirectoryClient(
    config,
    dependencies(async (url, init) => {
      calls.push({ url, init });
      return calls.length === 1
        ? reply(tokenDocument())
        : reply(directoryDocument([
            {
              alias: "pairwise.alias-7",
              identity_class: "full",
              current_full_relation_satisfied: true
            }
          ]));
    })
  );

  const result = await client.readForViewer({
    viewerAccessToken: "canonical-human-oauth-bearer"
  });

  assert.equal(calls[0].url, config.serviceTokenUrl);
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(
    [...new URLSearchParams(calls[0].init.body)].map(([name, value]) =>
      name === "client_assertion" ? [name, "<jwt>"] : [name, value]
    ),
    [
      ["grant_type", "client_credentials"],
      ["client_id", config.clientId],
      ["scope", FULL_DIRECTORY_SCOPE],
      ["client_assertion_type", CLIENT_ASSERTION_TYPE],
      ["client_assertion", "<jwt>"]
    ]
  );
  assert.equal(calls[1].url, config.directoryUrl);
  assert.equal(calls[1].init.method, "GET");
  assert.equal(
    calls[1].init.headers.Authorization,
    "Bearer request-scoped-service-bearer"
  );
  assert.equal(
    calls[1].init.headers["X-HODLXXI-Viewer-Authorization"],
    "Bearer canonical-human-oauth-bearer"
  );
  assert.notEqual(
    calls[1].init.headers.Authorization,
    calls[1].init.headers["X-HODLXXI-Viewer-Authorization"]
  );
  assert.deepEqual(result, {
    state: "available",
    participants: [{ alias: "pairwise.alias-7" }]
  });
  assert.doesNotMatch(JSON.stringify(result), /identity_class|relation|bearer/);
});

test("configuration and signing key loading fail closed with fixed diagnostics", async () => {
  for (const candidate of [
    undefined,
    { ...config, enabled: false },
    { ...config, clientId: "" },
    { ...config, audience: "http://ubid.internal.example/token" },
    { ...config, signingKeyPath: "relative.pem" },
    { ...config, tokenTimeoutMs: 10 }
  ]) {
    await assert.rejects(
      createUbidFullDirectoryClient(candidate, dependencies(async () => {
        assert.fail("invalid config must not call transport");
      })),
      { message: "full_directory_unavailable" }
    );
  }

  await assert.rejects(
    createUbidFullDirectoryClient(config, {
      ...dependencies(async () => assert.fail("must not fetch")),
      readFileImpl: async () => "not a private key"
    }),
    { message: "full_directory_unavailable" }
  );
});

test("service token validation is exact short-lived and has no stale fallback", async () => {
  for (const value of [
    { ...tokenDocument(), token_type: "bearer" },
    { ...tokenDocument(), expires_in: 0 },
    { ...tokenDocument(), expires_in: 301 },
    { ...tokenDocument(), expires_in: 1.5 },
    { ...tokenDocument(), scope: "openid" },
    { ...tokenDocument(), extra: true },
    { access_token: "x", token_type: "Bearer", expires_in: 60 }
  ]) {
    assert.throws(
      () => validateServiceTokenResponse(value),
      { message: "full_directory_unavailable" }
    );
  }

  let calls = 0;
  const client = await createUbidFullDirectoryClient(
    config,
    dependencies(async () => {
      calls += 1;
      if (calls === 1) return reply(tokenDocument());
      if (calls === 2) return reply(directoryDocument());
      return reply({ ...tokenDocument(), scope: "wrong" });
    })
  );
  await client.readForViewer({ viewerAccessToken: "human-bearer" });
  await assert.rejects(
    client.readForViewer({ viewerAccessToken: "human-bearer" }),
    { message: "full_directory_unavailable" }
  );
  assert.equal(calls, 3);
});

test("directory contract rejects malformed, extra, and identity-bearing data", () => {
  const hostile = [
    { ...directoryDocument(), extra: true },
    { ...directoryDocument(), schema: "wrong" },
    { ...directoryDocument(), version: 2 },
    directoryDocument([{
      alias: "safe-alias",
      identity_class: "full",
      current_full_relation_satisfied: true,
      subject: "a".repeat(64)
    }]),
    directoryDocument([{
      alias: "a".repeat(64),
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "xpub661MyMwAqRbc",
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "person@example.com",
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "npub1syntheticidentity",
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "1234567890",
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: `1${"A".repeat(25)}`,
      identity_class: "full",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "safe-alias",
      identity_class: "limited",
      current_full_relation_satisfied: true
    }]),
    directoryDocument([{
      alias: "safe-alias",
      identity_class: "full",
      current_full_relation_satisfied: false
    }])
  ];
  for (const value of hostile) {
    assert.throws(
      () => normalizeUbidFullDirectory(value, config),
      { message: "full_directory_unavailable" }
    );
  }
});

test("UBID denial and unavailability return one sanitized failure with no population", async () => {
  const privateMarkers = [
    privatePem.split("\n")[1],
    "human-bearer-private",
    "request-scoped-service-bearer",
    "private-upstream-body"
  ];
  for (const status of [401, 403, 404, 503]) {
    let calls = 0;
    const client = await createUbidFullDirectoryClient(
      config,
      dependencies(async () => {
        calls += 1;
        return calls === 1
          ? reply(tokenDocument())
          : reply({ error: "private-upstream-body", participants: [1] }, status);
      })
    );
    const error = await client.readForViewer({
      viewerAccessToken: "human-bearer-private"
    }).then(() => null, (caught) => caught);
    assert.equal(error?.message, "full_directory_unavailable");
    for (const marker of privateMarkers) {
      assert.equal(String(error).includes(marker), false);
    }
  }
});

test("missing viewer bearer is rejected before service-token acquisition", async () => {
  let calls = 0;
  const client = await createUbidFullDirectoryClient(
    config,
    dependencies(async () => {
      calls += 1;
      return reply(tokenDocument());
    })
  );
  for (const viewerAccessToken of [undefined, "", "bad bearer"]) {
    await assert.rejects(
      client.readForViewer({ viewerAccessToken }),
      { message: "full_directory_unavailable" }
    );
  }
  assert.equal(calls, 0);
});

test("a service token cannot be substituted for the human viewer credential", async () => {
  let calls = 0;
  const client = await createUbidFullDirectoryClient(
    config,
    dependencies(async () => {
      calls += 1;
      return reply(tokenDocument({ access_token: "same-bearer" }));
    })
  );
  await assert.rejects(
    client.readForViewer({ viewerAccessToken: "same-bearer" }),
    { message: "full_directory_unavailable" }
  );
  assert.equal(calls, 1);
});
