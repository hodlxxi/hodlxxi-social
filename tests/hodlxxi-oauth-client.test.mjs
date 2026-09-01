import test from "node:test";
import assert from "node:assert/strict";
import {
  createPkceChallenge,
  createHodlxxiOAuthClient,
  validateTokenResponse,
  validateIntrospectionResponse
} from "../src/server/hodlxxi-oauth-client.mjs";

const config = {
  authorityOrigin: "https://authority.example",
  callbackUri: "https://social.example/auth/callback",
  clientId: "social",
  clientSecret: "client-secret-private",
  scope: "openid",
  outboundTimeoutMs: 1000
};
const credentials = { code: "authorization-code", verifier: "v".repeat(43) };
const encoder = new TextEncoder();
const inertTimers = { setTimeoutImpl: () => 1, clearTimeoutImpl() {} };

const streamingReply = (raw, headers = {}) => {
  const bytes = encoder.encode(raw);
  return {
    status: 200,
    headers: new Headers({ "content-type": "application/json", ...headers }),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      }
    })
  };
};
const reply = (body) => streamingReply(JSON.stringify(body));

function trackedBody(chunks, { readError, cancelImpl, onRead } = {}) {
  const queue = (Array.isArray(chunks) ? chunks : [chunks]).map((chunk) => typeof chunk === "string" ? encoder.encode(chunk) : chunk);
  const state = { getReaderCalls: 0, readCalls: 0, releaseCalls: 0, cancelCalls: 0, consumed: false };
  let offset = 0;
  return {
    state,
    body: {
      getReader() {
        state.getReaderCalls += 1;
        return {
          async read() {
            state.readCalls += 1;
            onRead?.();
            if (readError) throw readError;
            if (offset < queue.length) return { done: false, value: queue[offset++] };
            state.consumed = true;
            return { done: true, value: undefined };
          },
          releaseLock() { state.releaseCalls += 1; }
        };
      },
      cancel() {
        state.cancelCalls += 1;
        return cancelImpl?.();
      }
    }
  };
}

function responseFor(body, { status = 200, statusText = "", contentType = "application/json", contentLength = null, headers } = {}) {
  return {
    status,
    statusText,
    headers: headers ?? {
      get(name) {
        if (name.toLowerCase() === "content-type") return contentType;
        if (name.toLowerCase() === "content-length") return contentLength;
        return null;
      }
    },
    body
  };
}

function clientWith(fetchImpl, dependencies = {}) {
  return createHodlxxiOAuthClient(config, { fetchImpl, ...inertTimers, ...dependencies });
}

async function expectOAuthFailure(promise) {
  const error = await promise.then(() => null, (caught) => caught);
  assert.ok(error instanceof Error);
  assert.equal(error.message, "oauth_request_failed");
  assert.equal(String(error), "Error: oauth_request_failed");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return error;
}

test("PKCE S256 matches RFC vector", () => assert.equal(
  createPkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
  "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
));

test("exchange and introspection use exact confidential endpoints and forms", async () => {
  const calls = [];
  const client = clientWith(async (url, init) => {
    calls.push([url, init]);
    return reply(calls.length === 1
      ? { access_token: "token", id_token: "header.payload.signature", token_type: "Bearer" }
      : { active: true, sub: "a".repeat(64), client_id: "social", scope: "openid" });
  });
  assert.deepEqual(await client.authenticate(credentials), {
    subject: "a".repeat(64),
    accessToken: "token"
  });
  assert.deepEqual(calls.map(([url]) => url), [
    "https://authority.example/oauth/token",
    "https://authority.example/oauth/introspect"
  ]);
  assert.deepEqual([...new URLSearchParams(calls[0][1].body)], [
    ["grant_type", "authorization_code"],
    ["code", "authorization-code"],
    ["redirect_uri", "https://social.example/auth/callback"],
    ["client_id", "social"],
    ["client_secret", "client-secret-private"],
    ["code_verifier", "v".repeat(43)]
  ]);
  assert.deepEqual([...new URLSearchParams(calls[1][1].body)], [
    ["token", "token"],
    ["client_id", "social"],
    ["client_secret", "client-secret-private"]
  ]);
  assert.doesNotMatch(calls[0][0], /client-secret-private/);
});

test("strict token and introspection shapes fail closed", () => {
  const accessor = { token_type: "Bearer" };
  Object.defineProperty(accessor, "access_token", { enumerable: true, get() { return "x"; } });
  for (const value of [
    { access_token: "x", token_type: "bearer" },
    { access_token: "x", token_type: "Bearer", extra: { nested: true } },
    { access_token: "x", token_type: "Bearer", scope: ["openid"] },
    { access_token: "x", token_type: "Bearer", id_token: {} },
    { access_token: "x", token_type: "Bearer", id_token: "" },
    accessor,
    [],
    Object.create({ access_token: "x", token_type: "Bearer" })
  ]) assert.throws(() => validateTokenResponse(value));
  for (const value of [
    { active: 1, sub: "a".repeat(64) },
    { active: true, sub: "A".repeat(64) },
    { active: true, sub: "02" + "a".repeat(64) },
    { active: true, sub: "a".repeat(64), exp: Infinity },
    { active: true, sub: "a".repeat(64), exp: -1 },
    { active: true, sub: "a".repeat(64), exp: 1.5 }
  ]) assert.throws(() => validateIntrospectionResponse(value, config));
});

test("duplicate token and introspection JSON members are rejected and disposed", async () => {
  const cases = [
    ['{"access_token":"first","access_token":"second","token_type":"Bearer"}'],
    [
      '{"access_token":"token","token_type":"Bearer"}',
      '{"active":true,"sub":"' + "a".repeat(64) + '","sub":"' + "b".repeat(64) + '"}'
    ]
  ];
  for (const bodies of cases) {
    const signals = [];
    const records = [];
    let calls = 0;
    const client = clientWith(async (_url, init) => {
      signals.push(init.signal);
      const record = trackedBody(bodies[calls++]);
      records.push(record);
      return responseFor(record.body);
    });
    await expectOAuthFailure(client.authenticate(credentials));
    assert.equal(calls, bodies.length);
    assert.equal(signals.at(-1).aborted, true);
    assert.equal(records.at(-1).state.cancelCalls, 1);
    if (signals.length === 2) {
      assert.equal(signals[0].aborted, false);
      assert.equal(records[0].state.cancelCalls, 0);
    }
  }
});

test("non-success response aborts before one idempotent cancellation and is never read", async () => {
  let signal;
  let calls = 0;
  let headerReads = 0;
  const clearObservations = [];
  const record = trackedBody("hostile-body-private", {
    cancelImpl() { assert.equal(signal.aborted, true); }
  });
  const client = clientWith(async (_url, init) => {
    calls += 1;
    signal = init.signal;
    return responseFor(record.body, {
      status: 503,
      statusText: "hostile-status-private",
      headers: { get() { headerReads += 1; return "hostile-header-private"; } }
    });
  }, {
    clearTimeoutImpl() { clearObservations.push([signal.aborted, record.state.cancelCalls]); }
  });
  await expectOAuthFailure(client.authenticate(credentials));
  assert.equal(calls, 1);
  assert.equal(signal.aborted, true);
  assert.equal(record.state.cancelCalls, 1);
  assert.equal(record.state.getReaderCalls, 0);
  assert.equal(headerReads, 0);
  assert.deepEqual(clearObservations, [[true, 1]]);
});

test("missing, malformed, and unsupported Content-Type abort and cancel without reading", async () => {
  const contentTypes = [null, "application/json;", "application/json; charset", "text/plain"];
  for (const contentType of contentTypes) {
    let signal;
    const clearObservations = [];
    const record = trackedBody("hostile-body-private");
    const client = clientWith(async (_url, init) => {
      signal = init.signal;
      return responseFor(record.body, { contentType });
    }, {
      clearTimeoutImpl() { clearObservations.push([signal.aborted, record.state.cancelCalls]); }
    });
    await expectOAuthFailure(client.authenticate(credentials));
    assert.equal(signal.aborted, true);
    assert.equal(record.state.cancelCalls, 1);
    assert.equal(record.state.getReaderCalls, 0);
    assert.deepEqual(clearObservations, [[true, 1]]);
  }
});

test("missing body or cancel method still terminates the request controller", async () => {
  for (const body of [null, { getReader() { assert.fail("rejected body must not be read"); } }]) {
    let signal;
    let clearedAborted = false;
    const client = clientWith(async (_url, init) => {
      signal = init.signal;
      return responseFor(body, { contentType: body === null ? "application/json" : "text/plain" });
    }, {
      clearTimeoutImpl() { clearedAborted = signal.aborted; }
    });
    await expectOAuthFailure(client.authenticate(credentials));
    assert.equal(signal.aborted, true);
    assert.equal(clearedAborted, true);
  }
});

test("throwing cancellation cannot replace the sanitized OAuth failure", async () => {
  let signal;
  const marker = "hostile-synchronous-cancel-private";
  const record = trackedBody("ignored", { cancelImpl() { throw new Error(marker); } });
  const client = clientWith(async (_url, init) => {
    signal = init.signal;
    return responseFor(record.body, { status: 502, statusText: marker });
  });
  const error = await expectOAuthFailure(client.authenticate(credentials));
  assert.equal(signal.aborted, true);
  assert.equal(record.state.cancelCalls, 1);
  assert.doesNotMatch(String(error), new RegExp(marker));
});

test("rejecting cancellation is handled without an unhandled rejection", async () => {
  const unhandled = [];
  const listener = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", listener);
  try {
    let signal;
    const marker = "hostile-rejected-cancel-private";
    const record = trackedBody("ignored", { cancelImpl() { return Promise.reject(new Error(marker)); } });
    const client = clientWith(async (_url, init) => {
      signal = init.signal;
      return responseFor(record.body, { status: 500 });
    });
    const error = await expectOAuthFailure(client.authenticate(credentials));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(signal.aborted, true);
    assert.equal(record.state.cancelCalls, 1);
    assert.deepEqual(unhandled, []);
    assert.doesNotMatch(String(error), new RegExp(marker));
  } finally {
    process.removeListener("unhandledRejection", listener);
  }
});

test("a pending cancellation promise is initiated but never awaited", async () => {
  let signal;
  const record = trackedBody("ignored", { cancelImpl() { return new Promise(() => {}); } });
  const client = clientWith(async (_url, init) => {
    signal = init.signal;
    return responseFor(record.body, { status: 500 });
  });
  const outcome = client.authenticate(credentials).then(() => "accepted", (error) => error.message);
  const settled = await Promise.race([
    outcome,
    new Promise((resolve) => setImmediate(() => resolve("still-pending")))
  ]);
  assert.equal(settled, "oauth_request_failed");
  assert.equal(signal.aborted, true);
  assert.equal(record.state.cancelCalls, 1);
});

test("oversize, read, decode, parse, duplicate, and token-schema failures terminate transport", async (t) => {
  const stages = [
    {
      name: "declared oversize",
      create: () => ({ record: trackedBody('{"access_token":"token","token_type":"Bearer"}'), contentLength: "16385", unread: true })
    },
    {
      name: "streamed oversize",
      create: () => ({ record: trackedBody([new Uint8Array(9000), new Uint8Array(9000)]) })
    },
    {
      name: "body read failure",
      create: () => ({ record: trackedBody("ignored", { readError: new Error("hostile-read-private") }) })
    },
    {
      name: "invalid UTF-8",
      create: () => ({ record: trackedBody(new Uint8Array([0xc3, 0x28])), consumed: true })
    },
    {
      name: "malformed JSON",
      create: () => ({ record: trackedBody('{"hostile-body-private":'), consumed: true })
    },
    {
      name: "duplicate JSON members",
      create: () => ({ record: trackedBody('{"access_token":"first","access_token":"second","token_type":"Bearer"}'), consumed: true })
    },
    {
      name: "token response schema",
      create: () => ({ record: trackedBody('{"access_token":"upstream-token-private","token_type":"bearer"}'), consumed: true })
    }
  ];
  for (const stage of stages) await t.test(stage.name, async () => {
    const { record, contentLength = null, unread = false, consumed = false } = stage.create();
    let signal;
    let calls = 0;
    const clearObservations = [];
    const client = clientWith(async (_url, init) => {
      calls += 1;
      signal = init.signal;
      return responseFor(record.body, { contentLength });
    }, {
      clearTimeoutImpl() { clearObservations.push([signal.aborted, record.state.cancelCalls]); }
    });
    await expectOAuthFailure(client.authenticate(credentials));
    assert.equal(calls, 1);
    assert.equal(signal.aborted, true);
    assert.equal(record.state.cancelCalls, 1);
    assert.deepEqual(clearObservations, [[true, 1]]);
    if (unread) assert.equal(record.state.getReaderCalls, 0);
    if (consumed) assert.equal(record.state.consumed, true);
  });
});

test("introspection schema failure aborts its consumed response but not the accepted token response", async () => {
  const signals = [];
  const records = [];
  const raws = [
    '{"access_token":"sensitive-upstream-token","token_type":"Bearer"}',
    '{"active":false,"sub":"' + "a".repeat(64) + '"}'
  ];
  let calls = 0;
  const client = clientWith(async (_url, init) => {
    signals.push(init.signal);
    const record = trackedBody(raws[calls++]);
    records.push(record);
    return responseFor(record.body);
  });
  const error = await expectOAuthFailure(client.authenticate(credentials));
  assert.equal(calls, 2);
  assert.equal(signals[0].aborted, false);
  assert.equal(records[0].state.cancelCalls, 0);
  assert.equal(signals[1].aborted, true);
  assert.equal(records[1].state.consumed, true);
  assert.equal(records[1].state.cancelCalls, 1);
  assert.doesNotMatch(String(error), /sensitive-upstream-token/);
});

test("fully accepted responses stay un-aborted through bounded consumption and validation", async () => {
  const payloads = [
    { access_token: "token", token_type: "Bearer" },
    { active: true, sub: "a".repeat(64), client_id: "social", scope: "openid" }
  ];
  const contentTypes = ["application/json; charset=utf-8", 'Application/JSON ; charset="utf-8"'];
  const signals = [];
  const records = [];
  const abortedDuringRead = [];
  const clearObservations = [];
  let calls = 0;
  const client = clientWith(async (_url, init) => {
    const index = calls++;
    signals.push(init.signal);
    const record = trackedBody(JSON.stringify(payloads[index]), {
      onRead() { abortedDuringRead.push(init.signal.aborted); }
    });
    records.push(record);
    return responseFor(record.body, { contentType: contentTypes[index] });
  }, {
    clearTimeoutImpl() {
      const index = clearObservations.length;
      clearObservations.push([signals[index].aborted, records[index].state.consumed, records[index].state.cancelCalls]);
    }
  });
  assert.deepEqual(await client.authenticate(credentials), {
    subject: "a".repeat(64),
    accessToken: "token"
  });
  assert.equal(calls, 2);
  assert.deepEqual(abortedDuringRead, [false, false, false, false]);
  assert.deepEqual(signals.map((signal) => signal.aborted), [false, false]);
  assert.deepEqual(clearObservations, [[false, true, 0], [false, true, 0]]);
});

test("public failures disclose no secret, token, body, status, header, URL, or cleanup exception", async () => {
  const token = "sensitive-upstream-token-private";
  const markers = [
    config.clientSecret,
    token,
    "hostile-body-private",
    "hostile-status-private",
    "hostile-header-private",
    "hostile-cancel-private",
    "https://authority.example/oauth/token",
    "https://authority.example/oauth/introspect"
  ];
  const signals = [];
  let calls = 0;
  const rejected = trackedBody("hostile-body-private", {
    cancelImpl() { throw new Error("hostile-cancel-private"); }
  });
  const client = clientWith(async (_url, init) => {
    signals.push(init.signal);
    calls += 1;
    if (calls === 1) return reply({ access_token: token, token_type: "Bearer" });
    return responseFor(rejected.body, {
      status: 502,
      statusText: "hostile-status-private",
      headers: { get() { return "hostile-header-private"; } }
    });
  });
  const error = await expectOAuthFailure(client.authenticate(credentials));
  assert.equal(calls, 2);
  assert.equal(signals[0].aborted, false);
  assert.equal(signals[1].aborted, true);
  assert.equal(rejected.state.getReaderCalls, 0);
  assert.equal(rejected.state.cancelCalls, 1);
  for (const marker of markers) assert.equal(String(error).includes(marker), false);
});
