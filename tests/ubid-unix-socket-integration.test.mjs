import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CLIENT_ASSERTION_TYPE,
  createUbidFullDirectoryClient,
  FULL_DIRECTORY_SCOPE,
  UBID_FULL_DIRECTORY_SCHEMA,
  UBID_FULL_DIRECTORY_VERSION
} from "../src/server/ubid-full-directory-client.mjs";
import {
  createUbidUnixSocketTransport,
  UBID_FULL_DIRECTORY_PATH,
  UBID_SERVICE_TOKEN_PATH
} from "../src/server/ubid-unix-socket-transport.mjs";

const serviceTokenUrl =
  `https://private-ubid.invalid${UBID_SERVICE_TOKEN_PATH}`;
const directoryUrl =
  `https://private-ubid.invalid${UBID_FULL_DIRECTORY_PATH}`;
const tokenDocument = JSON.stringify({
  access_token: "synthetic-service-bearer",
  token_type: "Bearer",
  expires_in: 60,
  scope: FULL_DIRECTORY_SCOPE
});
const directoryDocument = JSON.stringify({
  schema: UBID_FULL_DIRECTORY_SCHEMA,
  version: UBID_FULL_DIRECTORY_VERSION,
  participants: [{
    alias: "member~integration",
    identity_class: "full",
    current_full_relation_satisfied: true
  }]
});

const transportConfig = (socketPath) => Object.freeze({
  socketPath,
  serviceTokenUrl,
  directoryUrl
});
const clientConfig = Object.freeze({
  enabled: true,
  serviceTokenUrl,
  directoryUrl,
  clientId: "synthetic-social-client",
  clientSigningKeyId: "synthetic-key-id",
  tokenEndpointAudience: "urn:synthetic:ubid:token-endpoint",
  signingKeyPath: "/run/credentials/synthetic-social-key.pem",
  tokenTimeoutMs: 250,
  requestTimeoutMs: 250
});

const tokenInit = (signal) => ({
  method: "POST",
  headers: {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  body: "grant_type=client_credentials",
  credentials: "omit",
  redirect: "error",
  signal
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

const createClient = async (socketPath) => {
  const fetchImpl = createUbidUnixSocketTransport(
    transportConfig(socketPath)
  );
  return createUbidFullDirectoryClient(
    clientConfig,
    syntheticKeyDependencies(fetchImpl)
  );
};

const listen = (server, socketPath) => new Promise((resolve, reject) => {
  const failed = (error) => {
    server.removeListener("listening", ready);
    reject(error);
  };
  const ready = () => {
    server.removeListener("error", failed);
    resolve();
  };
  server.once("error", failed);
  server.once("listening", ready);
  server.listen(socketPath);
});

const close = async (server, sockets) => {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) return;
  await new Promise((resolve) => server.close(resolve));
};

const withUnixServer = async (handler, run) => {
  const directory = await mkdtemp(join(tmpdir(), "hxxi-social-uds-"));
  const socketPath = join(directory, "ubid.sock");
  const sockets = new Set();
  const server = http.createServer(handler);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  try {
    await listen(server, socketPath);
    return await run({ socketPath, sockets });
  } finally {
    await close(server, sockets);
    await rm(directory, { recursive: true, force: true });
    await assert.rejects(access(directory), { code: "ENOENT" });
  }
};

const readRequest = async (request) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
};

const jsonResponse = (response, body) => {
  response.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    Connection: "close"
  });
  response.end(body);
};

const within = async (promise, milliseconds = 1500) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("offline_unix_socket_test_timeout")),
          milliseconds
        );
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const waitFor = async (predicate, milliseconds = 1000) => {
  const deadline = Date.now() + milliseconds;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      assert.fail("offline Unix-socket cleanup did not complete");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};

test("real Unix socket carries the exact token and directory requests", async () => {
  const received = [];
  let handlerFailure;
  await withUnixServer(async (request, response) => {
    try {
      const body = await readRequest(request);
      received.push({
        method: request.method,
        url: request.url,
        headers: { ...request.headers },
        body
      });
      if (request.url === UBID_SERVICE_TOKEN_PATH) {
        jsonResponse(response, tokenDocument);
      } else if (request.url === UBID_FULL_DIRECTORY_PATH) {
        jsonResponse(response, directoryDocument);
      } else {
        response.destroy();
      }
    } catch (error) {
      handlerFailure = error;
      response.destroy();
    }
  }, async ({ socketPath, sockets }) => {
    const client = await createClient(socketPath);
    const result = await within(client.readForViewer({
      viewerAccessToken: "synthetic-viewer-bearer"
    }));
    assert.deepEqual(result, {
      state: "available",
      participants: [{ alias: "member~integration" }]
    });
    assert.equal(handlerFailure, undefined);
    assert.equal(received.length, 2);
    assert.deepEqual(
      received.map(({ method, url }) => [method, url]),
      [
        ["POST", UBID_SERVICE_TOKEN_PATH],
        ["GET", UBID_FULL_DIRECTORY_PATH]
      ]
    );
    for (const request of received) {
      assert.equal(request.headers.host, "private-ubid.invalid");
    }
    assert.equal(
      received[0].headers["content-type"],
      "application/x-www-form-urlencoded"
    );
    const form = new URLSearchParams(received[0].body);
    assert.deepEqual([...form.keys()], [
      "grant_type",
      "client_id",
      "scope",
      "client_assertion_type",
      "client_assertion"
    ]);
    assert.equal(form.get("grant_type"), "client_credentials");
    assert.equal(form.get("client_id"), clientConfig.clientId);
    assert.equal(form.get("scope"), FULL_DIRECTORY_SCOPE);
    assert.equal(
      form.get("client_assertion_type"),
      CLIENT_ASSERTION_TYPE
    );
    assert.match(
      form.get("client_assertion"),
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
    );
    assert.equal(
      received[1].headers.authorization,
      "Bearer synthetic-service-bearer"
    );
    assert.equal(
      received[1].headers["x-hodlxxi-viewer-authorization"],
      "Bearer synthetic-viewer-bearer"
    );
    assert.notEqual(
      received[1].headers.authorization,
      received[1].headers["x-hodlxxi-viewer-authorization"]
    );
    await waitFor(() => sockets.size === 0);
  });
});

test("real Unix socket refusal, pre-abort, reset, streaming abort, and timeout settle once", async (context) => {
  await context.test("socket refusal", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hxxi-refused-"));
    const missingSocket = join(directory, "missing.sock");
    try {
      const transport = createUbidUnixSocketTransport(
        transportConfig(missingSocket)
      );
      let completions = 0;
      const pending = transport(
        serviceTokenUrl,
        tokenInit(new AbortController().signal)
      );
      pending.then(
        () => { completions += 1; },
        () => { completions += 1; }
      );
      await assert.rejects(within(pending), {
        message: "full_directory_unavailable"
      });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(completions, 1);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  await context.test("already-aborted signal performs no socket request", async () => {
    let requests = 0;
    await withUnixServer((_request, response) => {
      requests += 1;
      response.destroy();
    }, async ({ socketPath }) => {
      const controller = new AbortController();
      controller.abort();
      const transport = createUbidUnixSocketTransport(
        transportConfig(socketPath)
      );
      await assert.rejects(
        within(transport(serviceTokenUrl, tokenInit(controller.signal))),
        { message: "full_directory_unavailable" }
      );
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(requests, 0);
    });
  });

  await context.test("peer reset rejects exactly once", async () => {
    let requests = 0;
    await withUnixServer((request) => {
      requests += 1;
      request.socket.destroy();
    }, async ({ socketPath, sockets }) => {
      const transport = createUbidUnixSocketTransport(
        transportConfig(socketPath)
      );
      let completions = 0;
      const pending = transport(
        serviceTokenUrl,
        tokenInit(new AbortController().signal)
      );
      pending.then(
        () => { completions += 1; },
        () => { completions += 1; }
      );
      await assert.rejects(within(pending), {
        message: "full_directory_unavailable"
      });
      await waitFor(() => sockets.size === 0);
      assert.equal(requests, 1);
      assert.equal(completions, 1);
    });
  });

  await context.test("early response close destroys the incomplete body", async () => {
    let responseClosed = false;
    await withUnixServer((_request, response) => {
      response.once("close", () => { responseClosed = true; });
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": "32",
        Connection: "close"
      });
      response.write("{\"partial\":");
      response.socket.destroy();
    }, async ({ socketPath, sockets }) => {
      const transport = createUbidUnixSocketTransport(
        transportConfig(socketPath)
      );
      await assert.rejects(
        within((async () => {
          const response = await transport(
            serviceTokenUrl,
            tokenInit(new AbortController().signal)
          );
          const reader = response.body.getReader();
          try {
            while (!(await reader.read()).done) {}
          } finally {
            reader.releaseLock();
          }
        })()),
        { message: "full_directory_unavailable" }
      );
      await waitFor(() => responseClosed && sockets.size === 0);
    });
  });

  await context.test("abort destroys a response that is still streaming", async () => {
    let responseClosed = false;
    await withUnixServer((_request, response) => {
      response.once("close", () => { responseClosed = true; });
      response.writeHead(200, {
        "Content-Type": "application/json",
        Connection: "close"
      });
      response.write("{\"partial\":");
    }, async ({ socketPath, sockets }) => {
      const controller = new AbortController();
      const transport = createUbidUnixSocketTransport(
        transportConfig(socketPath)
      );
      let completions = 0;
      const pending = transport(
        serviceTokenUrl,
        tokenInit(controller.signal)
      );
      pending.then(
        () => { completions += 1; },
        () => { completions += 1; }
      );
      const response = await within(pending);
      const reader = response.body.getReader();
      try {
        const first = await within(reader.read());
        assert.equal(first.done, false);
        controller.abort();
        await assert.rejects(within(reader.read()));
      } finally {
        reader.releaseLock();
      }
      await waitFor(() => responseClosed && sockets.size === 0);
      assert.equal(completions, 1);
    });
  });

  await context.test("client timeout destroys a delayed response", async () => {
    let responseClosed = false;
    await withUnixServer((_request, response) => {
      response.once("close", () => { responseClosed = true; });
    }, async ({ socketPath, sockets }) => {
      const client = await createClient(socketPath);
      let completions = 0;
      const pending = client.readForViewer({
        viewerAccessToken: "synthetic-viewer-bearer"
      });
      pending.then(
        () => { completions += 1; },
        () => { completions += 1; }
      );
      await assert.rejects(within(pending), {
        message: "full_directory_unavailable"
      });
      await waitFor(() => responseClosed && sockets.size === 0);
      assert.equal(completions, 1);
    });
  });
});

const rawResponse = (lines, body = "") => Buffer.from(
  `${lines.join("\r\n")}\r\n\r\n${body}`,
  "latin1"
);

const responseSecurityCases = [
  {
    name: "missing content-type",
    hold: true,
    send(response) {
      response.writeHead(200, { Connection: "close" });
      response.write("{");
    }
  },
  {
    name: "incorrect content-type",
    hold: true,
    send(response) {
      response.writeHead(200, {
        "Content-Type": "text/plain",
        Connection: "close"
      });
      response.write("{}");
    }
  },
  {
    name: "malformed content-length",
    send(response) {
      response.socket.end(rawResponse([
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Content-Length: not-a-number",
        "Connection: close"
      ], "{}"));
    }
  },
  {
    name: "conflicting duplicate content-length",
    send(response) {
      response.socket.end(rawResponse([
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Content-Length: 2",
        "Content-Length: 3",
        "Connection: close"
      ], "{}"));
    }
  },
  {
    name: "duplicate JSON members",
    body: `{"schema":"wrong","schema":"${UBID_FULL_DIRECTORY_SCHEMA}","version":1,"participants":[]}`
  },
  {
    name: "invalid UTF-8",
    bytes: Buffer.from([0xff])
  },
  {
    name: "declared oversized body",
    hold: true,
    send(response) {
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": String(1024 * 1024 + 1),
        Connection: "close"
      });
      response.write("{");
    }
  },
  {
    name: "actually streamed oversized body",
    hold: true,
    send(response) {
      response.writeHead(200, {
        "Content-Type": "application/json",
        Connection: "close"
      });
      response.write(Buffer.alloc(1024 * 1024 + 1, 0x20));
    }
  },
  {
    name: "truncated JSON",
    body: "{\"schema\":"
  },
  {
    name: "malformed JSON",
    body: "{\"schema\":]"
  }
];

test("real client and transport preserve every response-security rejection", async (context) => {
  for (const fixture of responseSecurityCases) {
    await context.test(fixture.name, async () => {
      let directoryResponse;
      let directorySocket;
      let directoryClosed = false;
      let requests = 0;
      await withUnixServer((request, response) => {
        requests += 1;
        if (request.url === UBID_SERVICE_TOKEN_PATH) {
          jsonResponse(response, tokenDocument);
          return;
        }
        directoryResponse = response;
        directorySocket = response.socket;
        response.once("close", () => { directoryClosed = true; });
        if (fixture.send) {
          fixture.send(response);
          return;
        }
        const body = fixture.bytes ?? Buffer.from(fixture.body, "utf8");
        response.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": body.byteLength,
          Connection: "close"
        });
        response.end(body);
      }, async ({ socketPath, sockets }) => {
        const client = await createClient(socketPath);
        await assert.rejects(
          within(client.readForViewer({
            viewerAccessToken: "synthetic-viewer-bearer"
          }), 2500),
          (error) =>
            error?.message === "full_directory_unavailable" &&
            String(error) === "Error: full_directory_unavailable"
        );
        assert.equal(requests, 2);
        await waitFor(() =>
          directoryClosed &&
          directorySocket?.destroyed === true &&
          sockets.size === 0
        );
        if (fixture.hold) {
          assert.equal(directoryResponse.destroyed, true);
          assert.equal(directoryResponse.writableEnded, false);
        } else {
          assert.equal(
            directoryResponse.writableEnded || directorySocket.destroyed,
            true
          );
        }
      });
    });
  }
});
