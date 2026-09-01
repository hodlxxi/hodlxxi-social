import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";

import {
  createUbidUnixSocketTransport,
  UBID_FULL_DIRECTORY_PATH,
  UBID_SERVICE_TOKEN_PATH
} from "../src/server/ubid-unix-socket-transport.mjs";
import {
  createUbidFullDirectoryClient,
  FULL_DIRECTORY_SCOPE,
  UBID_FULL_DIRECTORY_SCHEMA,
  UBID_FULL_DIRECTORY_VERSION
} from "../src/server/ubid-full-directory-client.mjs";

const socketPath = "/run/hodlxxi/ubid-social-private.sock";
const serviceTokenUrl =
  `https://private-ubid.invalid${UBID_SERVICE_TOKEN_PATH}`;
const directoryUrl =
  `https://private-ubid.invalid${UBID_FULL_DIRECTORY_PATH}`;
const transportConfig = Object.freeze({
  socketPath,
  serviceTokenUrl,
  directoryUrl
});

const commonInit = (signal) => ({
  credentials: "omit",
  redirect: "error",
  signal
});
const tokenInit = (signal) => ({
  ...commonInit(signal),
  method: "POST",
  headers: {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  body: "grant_type=client_credentials"
});
const directoryInit = (signal) => ({
  ...commonInit(signal),
  method: "GET",
  headers: {
    Accept: "application/json",
    Authorization: "Bearer synthetic-service-bearer",
    "X-HODLXXI-Viewer-Authorization": "Bearer synthetic-viewer-bearer"
  }
});

const nodeResponse = ({
  statusCode = 200,
  rawHeaders = ["Content-Type", "application/json; charset=utf-8"],
  chunks = [Buffer.from("{}")]
} = {}) => {
  const response = Readable.from(chunks);
  response.statusCode = statusCode;
  response.rawHeaders = rawHeaders;
  return response;
};

const requestHarness = (responseFactory) => {
  const calls = [];
  const requestImpl = (options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.destroyedByTransport = false;
    outgoing.destroy = () => {
      outgoing.destroyedByTransport = true;
    };
    outgoing.end = (body) => {
      calls.push({ options, body, outgoing });
      queueMicrotask(() => responseFactory({ callback, outgoing, calls }));
    };
    return outgoing;
  };
  return { calls, requestImpl };
};

const consume = async (response) => {
  const reader = response.body.getReader();
  const chunks = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      chunks.push(Buffer.from(next.value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
};

test("Unix transport uses only socketPath and exact logical Host", async () => {
  const harness = requestHarness(({ callback }) => callback(nodeResponse()));
  const transport = createUbidUnixSocketTransport(
    transportConfig,
    { requestImpl: harness.requestImpl }
  );

  const tokenResponse = await transport(
    serviceTokenUrl,
    tokenInit(new AbortController().signal)
  );
  const directoryResponse = await transport(
    directoryUrl,
    directoryInit(new AbortController().signal)
  );
  assert.equal(await consume(tokenResponse), "{}");
  assert.equal(await consume(directoryResponse), "{}");
  assert.equal(harness.calls.length, 2);

  for (const { options } of harness.calls) {
    assert.equal(options.socketPath, socketPath);
    assert.equal(options.headers.Host, "private-ubid.invalid");
    for (const forbidden of [
      "host", "hostname", "port", "protocol", "agent", "proxy",
      "href", "origin"
    ]) assert.equal(Object.hasOwn(options, forbidden), false, forbidden);
  }
  assert.deepEqual(
    harness.calls.map(({ options }) => [options.method, options.path]),
    [
      ["POST", UBID_SERVICE_TOKEN_PATH],
      ["GET", UBID_FULL_DIRECTORY_PATH]
    ]
  );
  assert.equal(
    harness.calls[1].options.headers.authorization,
    "Bearer synthetic-service-bearer"
  );
  assert.equal(
    harness.calls[1].options.headers["x-hodlxxi-viewer-authorization"],
    "Bearer synthetic-viewer-bearer"
  );
  assert.notEqual(
    harness.calls[1].options.headers.authorization,
    harness.calls[1].options.headers["x-hodlxxi-viewer-authorization"]
  );
});

test("only the two exact URL and method pairs can reach Node HTTP", async () => {
  let networkCalls = 0;
  const transport = createUbidUnixSocketTransport(transportConfig, {
    requestImpl() {
      networkCalls += 1;
      throw new Error("must not reach transport");
    }
  });
  const rejected = [
    [serviceTokenUrl, { ...tokenInit(new AbortController().signal), method: "GET" }],
    [directoryUrl, { ...directoryInit(new AbortController().signal), method: "POST" }],
    [`${serviceTokenUrl}?scope=x`, tokenInit(new AbortController().signal)],
    [`${directoryUrl}#fragment`, directoryInit(new AbortController().signal)],
    ["https://private-ubid.invalid/internal/v1/social/service-token/", tokenInit(new AbortController().signal)],
    ["https://127.0.0.1/internal/v1/social/full-directory", directoryInit(new AbortController().signal)],
    [directoryUrl, { ...directoryInit(new AbortController().signal), redirect: "follow" }],
    [directoryUrl, { ...directoryInit(new AbortController().signal), proxy: "http://proxy.invalid" }],
    [directoryUrl, { ...directoryInit(new AbortController().signal), hostname: "127.0.0.1" }],
    [directoryUrl, {
      ...directoryInit(new AbortController().signal),
      headers: { ...directoryInit(new AbortController().signal).headers, Host: "hostile.invalid" }
    }]
  ];
  for (const [url, init] of rejected) {
    await assert.rejects(transport(url, init), {
      message: "full_directory_unavailable"
    });
  }
  assert.equal(networkCalls, 0);

  for (const patch of [
    { serviceTokenUrl: `${serviceTokenUrl}?query=1` },
    { directoryUrl: `${directoryUrl}#fragment` },
    { directoryUrl: "https://user:pass@private-ubid.invalid/internal/v1/social/full-directory" },
    { directoryUrl: "https://private-ubid.invalid/internal/v1/social/other" }
  ]) {
    assert.throws(
      () => createUbidUnixSocketTransport({ ...transportConfig, ...patch }),
      { message: "full_directory_unavailable" }
    );
  }
});

test("socket refusal, abort, request timeout, redirect, and malformed response metadata fail closed", async () => {
  const failures = [
    ({ outgoing }) => outgoing.emit("error", new Error(`${socketPath}: refused`)),
    ({ outgoing }) => outgoing.emit("timeout"),
    ({ callback }) => callback(nodeResponse({ statusCode: 302 })),
    ({ callback }) => callback(nodeResponse({ statusCode: 99 })),
    ({ callback }) => callback(nodeResponse({ rawHeaders: ["Content-Type"] })),
    ({ callback }) => callback(nodeResponse({
      rawHeaders: ["Content-Type", "application/json", "Content-Type", "text/plain"]
    }))
  ];
  for (const behavior of failures) {
    const harness = requestHarness(behavior);
    const transport = createUbidUnixSocketTransport(transportConfig, {
      requestImpl: harness.requestImpl
    });
    await assert.rejects(
      transport(serviceTokenUrl, tokenInit(new AbortController().signal)),
      (error) => error.message === "full_directory_unavailable" &&
        !String(error).includes(socketPath)
    );
  }

  const harness = requestHarness(() => {});
  const transport = createUbidUnixSocketTransport(transportConfig, {
    requestImpl: harness.requestImpl
  });
  const controller = new AbortController();
  const pending = transport(serviceTokenUrl, tokenInit(controller.signal));
  controller.abort();
  await assert.rejects(pending, { message: "full_directory_unavailable" });
  assert.equal(harness.calls[0].outgoing.destroyedByTransport, true);
});

const clientConfig = Object.freeze({
  enabled: true,
  serviceTokenUrl,
  directoryUrl,
  clientId: "synthetic-social-client",
  clientSigningKeyId: "synthetic-key-id",
  tokenEndpointAudience: "urn:synthetic:ubid:token-endpoint",
  signingKeyPath: "/run/credentials/synthetic-social-key.pem",
  tokenTimeoutMs: 1000,
  requestTimeoutMs: 1000
});

const syntheticKeyDependencies = (fetchImpl) => ({
  fetchImpl,
  openFileImpl: async () => {
    let read = false;
    return {
      async stat() {
        return { isFile: () => true, mode: 0o100600, size: 9 };
      },
      async read(buffer) {
        if (read) return { bytesRead: 0, buffer };
        read = true;
        Buffer.from("synthetic").copy(buffer);
        return { bytesRead: 9, buffer };
      },
      async close() {}
    };
  },
  createPrivateKeyImpl: () => ({
    type: "private",
    asymmetricKeyType: "rsa",
    asymmetricKeyDetails: { modulusLength: 2048 }
  }),
  signImpl: () => Buffer.from("synthetic-signature"),
  random: (size) => Buffer.alloc(size, 0x41),
  now: () => 1_800_000_000_000
});

const tokenDocument = JSON.stringify({
  access_token: "synthetic-service-bearer",
  token_type: "Bearer",
  expires_in: 60,
  scope: FULL_DIRECTORY_SCOPE
});
const directoryDocument = JSON.stringify({
  schema: UBID_FULL_DIRECTORY_SCHEMA,
  version: UBID_FULL_DIRECTORY_VERSION,
  participants: []
});

test("socket response bodies retain the existing malformed and size fail-closed boundary", async () => {
  const cases = [
    [Buffer.from([0xff]), ["Content-Type", "application/json"]],
    [Buffer.from("{\"schema\":"), ["Content-Type", "application/json"]],
    [Buffer.from(directoryDocument), [
      "Content-Type", "application/json",
      "Content-Length", String(1024 * 1024 + 1)
    ]]
  ];
  for (const [directoryBody, directoryHeaders] of cases) {
    let call = 0;
    const harness = requestHarness(({ callback }) => {
      call += 1;
      callback(nodeResponse({
        chunks: [call === 1 ? Buffer.from(tokenDocument) : directoryBody],
        rawHeaders: call === 1
          ? ["Content-Type", "application/json"]
          : directoryHeaders
      }));
    });
    const fetchImpl = createUbidUnixSocketTransport(transportConfig, {
      requestImpl: harness.requestImpl
    });
    const client = await createUbidFullDirectoryClient(
      clientConfig,
      syntheticKeyDependencies(fetchImpl)
    );
    await assert.rejects(
      client.readForViewer({ viewerAccessToken: "synthetic-viewer-bearer" }),
      { message: "full_directory_unavailable" }
    );
    assert.equal(call, 2);
  }
});

test("Unix transport never consults ambient fetch", async () => {
  const originalFetch = globalThis.fetch;
  let ambientCalls = 0;
  globalThis.fetch = async () => {
    ambientCalls += 1;
    throw new Error("ambient fetch prohibited");
  };
  try {
    const harness = requestHarness(({ callback }) => callback(nodeResponse()));
    const transport = createUbidUnixSocketTransport(transportConfig, {
      requestImpl: harness.requestImpl
    });
    const response = await transport(
      serviceTokenUrl,
      tokenInit(new AbortController().signal)
    );
    await consume(response);
    assert.equal(ambientCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("transport source imports no fallback network stack, proxy, dependency, or logger", async () => {
  const source = await readFile(
    new URL("../src/server/ubid-unix-socket-transport.mjs", import.meta.url),
    "utf8"
  );
  for (const forbidden of [
    /globalThis\.fetch/,
    /node:dns/,
    /node:net/,
    /node:https/,
    /console\./,
    /process\.env/
  ]) assert.doesNotMatch(source, forbidden);
  assert.deepEqual(
    [...source.matchAll(/from "([^"]+)"/g)].map((match) => match[1]),
    ["node:http", "node:stream", "./social-oauth-config.mjs"]
  );
});
