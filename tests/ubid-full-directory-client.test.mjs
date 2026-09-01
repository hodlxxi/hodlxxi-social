import test from "node:test";
import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  mkdtemp,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CLIENT_ASSERTION_GRANT_TYPE,
  CLIENT_ASSERTION_LIFETIME_SECONDS,
  CLIENT_ASSERTION_PURPOSE,
  CLIENT_ASSERTION_TOKEN_USE,
  CLIENT_ASSERTION_TYPE,
  createClientAssertion,
  createUbidFullDirectoryClient,
  FULL_DIRECTORY_SCOPE,
  normalizeUbidFullDirectory,
  UBID_FULL_DIRECTORY_SCHEMA,
  UBID_FULL_DIRECTORY_VERSION,
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
  clientId: "social-confidential-backend",
  clientSigningKeyId: "social-client-key-1",
  tokenEndpointAudience:
    "https://ubid.internal.example/internal/v1/social/service-token",
  signingKeyPath: "/run/credentials/hodlxxi-social/full-directory.pem",
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1500
});
const SERVICE_PRINCIPAL = "service:social-full-directory";

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
  schema: UBID_FULL_DIRECTORY_SCHEMA,
  version: UBID_FULL_DIRECTORY_VERSION,
  participants
});

const privatePemBytes = Buffer.from(privatePem);
const memoryKeyFile = (
  content,
  { mode = 0o100600, regular = true } = {}
) => {
  const bytes = Buffer.from(content);
  return async (path, flags) => {
    assert.equal(path, config.signingKeyPath);
    assert.equal((flags & fsConstants.O_NOFOLLOW) !== 0, true);
    let offset = 0;
    let closed = false;
    return {
      async stat() {
        return {
          isFile: () => regular,
          mode,
          size: bytes.byteLength
        };
      },
      async read(target, targetOffset, length) {
        assert.equal(closed, false);
        const bytesRead = Math.min(length, bytes.byteLength - offset);
        if (bytesRead > 0) {
          bytes.copy(
            target,
            targetOffset,
            offset,
            offset + bytesRead
          );
          offset += bytesRead;
        }
        return { bytesRead, buffer: target };
      },
      async close() {
        assert.equal(closed, false);
        closed = true;
      }
    };
  };
};
const inMemoryPrivateKeyFile = memoryKeyFile(privatePemBytes);

const dependencies = (fetchImpl, overrides = {}) => ({
  fetchImpl,
  openFileImpl: inMemoryPrivateKeyFile,
  now: () => 1_800_000_000_000,
  setTimeoutImpl: () => 1,
  clearTimeoutImpl() {},
  ...overrides
});

const decode = (part) => JSON.parse(Buffer.from(part, "base64url"));

const ubidClientJwks = Object.freeze([Object.freeze({
  ...publicKey.export({ format: "jwk" }),
  kid: config.clientSigningKeyId,
  use: "sig",
  alg: "RS256"
})]);

const ubidContractAccepts = (
  assertion,
  {
    clientId = config.clientId,
    tokenEndpointAudience = config.tokenEndpointAudience,
    clientJwks = ubidClientJwks,
    now = 1_800_000_000
  } = {}
) => {
  try {
    const [encodedHeader, encodedClaims, encodedSignature, extra] =
      assertion.split(".");
    if (extra !== undefined) return false;
    const header = decode(encodedHeader);
    if (
      header.alg !== "RS256" ||
      typeof header.kid !== "string" ||
      header.kid.length === 0 ||
      header.kid.length > 255 ||
      header.kid.trim() !== header.kid
    ) return false;
    const matches = clientJwks.filter((key) =>
      key?.kid === header.kid
    );
    if (matches.length !== 1) return false;
    const selected = matches[0];
    if (
      selected.kty !== "RSA" ||
      selected.use !== "sig" ||
      selected.alg !== "RS256"
    ) return false;
    const verificationKey = createPublicKey({
      key: selected,
      format: "jwk"
    });
    if (!verify(
      "RSA-SHA256",
      Buffer.from(`${encodedHeader}.${encodedClaims}`, "ascii"),
      verificationKey,
      Buffer.from(encodedSignature, "base64url")
    )) return false;
    const claims = decode(encodedClaims);
    return claims.iss === clientId &&
      claims.sub === clientId &&
      claims.aud === tokenEndpointAudience &&
      typeof claims.aud === "string" &&
      claims.token_use === CLIENT_ASSERTION_TOKEN_USE &&
      claims.grant_type === CLIENT_ASSERTION_GRANT_TYPE &&
      claims.purpose === CLIENT_ASSERTION_PURPOSE &&
      Number.isSafeInteger(claims.iat) &&
      Number.isSafeInteger(claims.exp) &&
      claims.exp > claims.iat &&
      claims.exp - claims.iat <= CLIENT_ASSERTION_LIFETIME_SECONDS &&
      claims.iat <= now + 5 &&
      claims.iat >= now - CLIENT_ASSERTION_LIFETIME_SECONDS - 5 &&
      claims.exp >= now - 5 &&
      typeof claims.jti === "string" &&
      claims.jti.length > 0 &&
      claims.jti.length <= 128 &&
      claims.jti.trim() === claims.jti;
  } catch {
    return false;
  }
};

const signedContractFixture = ({
  headerPatch = {},
  claimPatch = {},
  omit = []
} = {}) => {
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: config.clientSigningKeyId,
    ...headerPatch
  };
  const claims = {
    iss: config.clientId,
    sub: config.clientId,
    aud: config.tokenEndpointAudience,
    token_use: CLIENT_ASSERTION_TOKEN_USE,
    grant_type: CLIENT_ASSERTION_GRANT_TYPE,
    purpose: CLIENT_ASSERTION_PURPOSE,
    iat: 1_800_000_000,
    exp: 1_800_000_060,
    jti: "synthetic-cross-contract-jti",
    ...claimPatch
  };
  for (const name of omit) delete claims[name];
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
    "base64url"
  );
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString(
    "base64url"
  );
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = cryptoSign(
    "RSA-SHA256",
    Buffer.from(signingInput, "ascii"),
    privateKey
  );
  return `${signingInput}.${signature.toString("base64url")}`;
};

test("UBID contract compatibility rejects every PR-head assertion mismatch", () => {
  const accepted = createClientAssertion(config, privateKey, {
    now: () => 1_800_000_000_000,
    random: (size) => Buffer.alloc(size, 0x51)
  });
  assert.equal(ubidContractAccepts(accepted), true);

  const rejected = [
    signedContractFixture({ headerPatch: { kid: undefined } }),
    signedContractFixture({ headerPatch: { kid: "wrong-key" } }),
    signedContractFixture({ headerPatch: { alg: "HS256" } }),
    signedContractFixture({ claimPatch: { iss: "service-token-issuer" } }),
    signedContractFixture({ claimPatch: { sub: SERVICE_PRINCIPAL } }),
    signedContractFixture({ omit: ["grant_type"] }),
    signedContractFixture({ claimPatch: { purpose: "wrong" } }),
    signedContractFixture({ claimPatch: { token_use: "wrong" } }),
    signedContractFixture({ claimPatch: { aud: "wrong-audience" } })
  ];
  for (const assertion of rejected) {
    assert.equal(ubidContractAccepts(assertion), false);
  }
  assert.equal(ubidContractAccepts(accepted, {
    clientJwks: [ubidClientJwks[0], { ...ubidClientJwks[0] }]
  }), false);

  const prHeadContract = signedContractFixture({
    headerPatch: { kid: undefined },
    claimPatch: {
      iss: "configured-service-token-issuer",
      sub: SERVICE_PRINCIPAL
    },
    omit: ["grant_type"]
  });
  assert.equal(ubidContractAccepts(prHeadContract), false);
});

test("fresh RS256 assertion carries the exact UBID client-authentication contract", async () => {
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
      typ: "JWT",
      kid: config.clientSigningKeyId
    });
    const claims = decode(encodedClaims);
    assert.deepEqual(Object.keys(claims), [
      "iss",
      "sub",
      "aud",
      "token_use",
      "grant_type",
      "purpose",
      "iat",
      "exp",
      "jti"
    ]);
    assert.equal(claims.iss, config.clientId);
    assert.equal(claims.sub, config.clientId);
    assert.notEqual(claims.sub, SERVICE_PRINCIPAL);
    assert.equal(claims.aud, config.tokenEndpointAudience);
    assert.equal(claims.token_use, CLIENT_ASSERTION_TOKEN_USE);
    assert.equal(claims.grant_type, CLIENT_ASSERTION_GRANT_TYPE);
    assert.equal(claims.purpose, CLIENT_ASSERTION_PURPOSE);
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
    { ...config, clientSigningKeyId: "" },
    { ...config, clientSigningKeyId: "x".repeat(256) },
    { ...config, tokenEndpointAudience: "" },
    { ...config, tokenEndpointAudience: "unsafe\u0000audience" },
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
      openFileImpl: memoryKeyFile("not a private key")
    }),
    { message: "full_directory_unavailable" }
  );
});

test("service token validation is exact short-lived and has no stale fallback", async () => {
  for (const value of [
    { ...tokenDocument(), token_type: "bearer" },
    { ...tokenDocument(), expires_in: 0 },
    { ...tokenDocument(), expires_in: 59 },
    { ...tokenDocument(), expires_in: 61 },
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

test("opaque token-endpoint audiences are preserved exactly", async () => {
  const tokenEndpointAudience =
    "urn:hodlxxi:ubid:confidential-service-token";
  const assertion = createClientAssertion(
    { ...config, tokenEndpointAudience },
    privateKey,
    {
      now: () => 1_800_000_000_000,
      random: (size) => Buffer.alloc(size, 0x61)
    }
  );
  assert.equal(decode(assertion.split(".")[1]).aud, tokenEndpointAudience);
  assert.equal(ubidContractAccepts(assertion, {
    tokenEndpointAudience
  }), true);
});

test("Linux private-key loading rejects symlinks unsafe modes non-files oversize and weak RSA", async () => {
  const directory = await mkdtemp(join(
    tmpdir(),
    "hodlxxi-social-service-key-"
  ));
  const securePath = join(directory, "client-private.pem");
  const symlinkPath = join(directory, "client-private-link.pem");
  const oversizedPath = join(directory, "oversized.pem");
  const weakPath = join(directory, "weak.pem");
  const rejectPath = async (signingKeyPath) => {
    await assert.rejects(
      createUbidFullDirectoryClient({ ...config, signingKeyPath }),
      { message: "full_directory_unavailable" }
    );
  };

  try {
    await writeFile(securePath, privatePemBytes, { mode: 0o600 });
    await createUbidFullDirectoryClient({
      ...config,
      signingKeyPath: securePath
    });

    for (const mode of [0o640, 0o620, 0o604]) {
      await chmod(securePath, mode);
      await rejectPath(securePath);
    }
    await chmod(securePath, 0o600);

    await symlink(securePath, symlinkPath);
    await rejectPath(symlinkPath);
    await rejectPath(directory);

    await writeFile(
      oversizedPath,
      Buffer.alloc(32 * 1024 + 1, 0x41),
      { mode: 0o600 }
    );
    await rejectPath(oversizedPath);

    const weakPrivateKey = generateKeyPairSync("rsa", {
      modulusLength: 1024
    }).privateKey.export({ type: "pkcs8", format: "pem" });
    await writeFile(weakPath, weakPrivateKey, { mode: 0o600 });
    await rejectPath(weakPath);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
