import test from "node:test";
import assert from "node:assert/strict";

import {
  createRehearsalRuntime,
  createRehearsalHandler,
  parseRehearsalOptions,
  REHEARSAL_SUBJECT
} from "../scripts/hodlxxi-social-auth-rehearsal.mjs";

import {
  TRANSACTION_COOKIE_NAME,
  SESSION_COOKIE_NAME
} from "../src/server/social-oauth-cookie.mjs";

const deterministicRandom = (size) => Buffer.alloc(size, 0x31);

const cookiePair = (setCookie, name) => {
  const values = Array.isArray(setCookie) ? setCookie : [setCookie];
  const match = values.find(
    (value) =>
      typeof value === "string" &&
      value.startsWith(`${name}=`) &&
      !value.startsWith(`${name}=;`)
  );

  assert.ok(match, `missing ${name}`);
  return match.split(";", 1)[0];
};

const invoke = async (
  handler,
  {
    url,
    method = "GET",
    headers = {},
    rawHeaders = []
  }
) => {
  const outgoing = {
    statusCode: 0,
    headers: {},
    body: undefined,
    setHeader(name, value) {
      this.headers[name] = value;
    },
    end(body) {
      this.body = body;
    }
  };

  await handler(
    {
      url,
      method,
      headers,
      rawHeaders
    },
    outgoing
  );

  return outgoing;
};

const jsonBody = (result) =>
  JSON.parse(Buffer.isBuffer(result.body) ? result.body.toString("utf8") : result.body);

async function authenticatedFlow(status) {
  const runtime = createRehearsalRuntime({
    port: status === "full" ? 18444 : 18443,
    status,
    random: deterministicRandom
  });

  const handler = createRehearsalHandler({ runtime });

  const login = await invoke(handler, {
    url: "/auth/login"
  });

  assert.equal(login.statusCode, 302);
  assert.match(login.headers.Location, /^https:\/\/127\.0\.0\.1:\d+\/oauth\/authorize\?/);

  const transactionCookie = cookiePair(
    login.headers["Set-Cookie"],
    TRANSACTION_COOKIE_NAME
  );

  const authorizeUrl = new URL(login.headers.Location);
  const authorize = await invoke(handler, {
    url: `${authorizeUrl.pathname}${authorizeUrl.search}`
  });

  assert.equal(authorize.statusCode, 302);
  assert.match(
    authorize.headers.Location,
    /^\/auth\/callback\?code=hodlxxi-social-rehearsal-code&state=/
  );

  const callback = await invoke(handler, {
    url: authorize.headers.Location,
    headers: {
      cookie: transactionCookie
    }
  });

  assert.equal(callback.statusCode, 303);
  assert.equal(callback.headers.Location, "/");

  const sessionCookie = cookiePair(
    callback.headers["Set-Cookie"],
    SESSION_COOKIE_NAME
  );

  const session = await invoke(handler, {
    url: "/auth/session",
    headers: {
      cookie: sessionCookie
    }
  });

  assert.equal(session.statusCode, 200);
  assert.deepEqual(jsonBody(session), {
    authenticated: true,
    subject: REHEARSAL_SUBJECT
  });

  const authority = await invoke(handler, {
    url: "/auth/authority",
    headers: {
      cookie: sessionCookie
    }
  });

  assert.equal(authority.statusCode, 200);
  assert.deepEqual(jsonBody(authority), {
    subject: REHEARSAL_SUBJECT,
    status,
    valid: true
  });

  return {
    runtime,
    handler,
    sessionCookie
  };
}

test("rehearsal configuration is explicit and local TLS material must be absolute", () => {
  assert.deepEqual(
    parseRehearsalOptions({
      SOCIAL_REHEARSAL_PORT: "8443",
      SOCIAL_REHEARSAL_STATUS: "limited",
      SOCIAL_REHEARSAL_KEY: "/tmp/rehearsal.key",
      SOCIAL_REHEARSAL_CERT: "/tmp/rehearsal.crt"
    }),
    {
      port: 8443,
      status: "limited",
      keyPath: "/tmp/rehearsal.key",
      certPath: "/tmp/rehearsal.crt"
    }
  );

  for (const input of [
    {
      SOCIAL_REHEARSAL_PORT: "80",
      SOCIAL_REHEARSAL_STATUS: "limited",
      SOCIAL_REHEARSAL_KEY: "/tmp/key",
      SOCIAL_REHEARSAL_CERT: "/tmp/cert"
    },
    {
      SOCIAL_REHEARSAL_PORT: "8443",
      SOCIAL_REHEARSAL_STATUS: "operator",
      SOCIAL_REHEARSAL_KEY: "/tmp/key",
      SOCIAL_REHEARSAL_CERT: "/tmp/cert"
    },
    {
      SOCIAL_REHEARSAL_PORT: "8443",
      SOCIAL_REHEARSAL_STATUS: "full",
      SOCIAL_REHEARSAL_KEY: "relative.key",
      SOCIAL_REHEARSAL_CERT: "/tmp/cert"
    }
  ]) {
    assert.throws(
      () => parseRehearsalOptions(input),
      /invalid rehearsal configuration/
    );
  }
});

test("ordinary index is served with an unmistakable local rehearsal banner", async () => {
  const runtime = createRehearsalRuntime({
    port: 18443,
    status: "full",
    random: deterministicRandom
  });

  const result = await invoke(
    createRehearsalHandler({ runtime }),
    { url: "/" }
  );

  assert.equal(result.statusCode, 200);
  assert.equal(result.headers["X-HODLXXI-Rehearsal"], "local-only");
  assert.match(result.headers["Content-Type"], /^text\/html/);

  const html = Buffer.from(result.body).toString("utf8");

  assert.match(html, /LOCAL V1\.15 REHEARSAL/);
  assert.match(html, /synthetic OAuth identity/);
  assert.match(html, /synthetic FULL authority/);
  assert.match(html, /auth-entry\.mjs/);
  assert.doesNotMatch(html, /hodlxxi\.com/);
});

test("rehearsal serves only the exact authenticated asset revision query", async () => {
  const runtime = createRehearsalRuntime({
    port: 18443,
    status: "full",
    random: deterministicRandom
  });
  const handler = createRehearsalHandler({ runtime });

  for (const path of [
    "/styles.css?v=1.24.0",
    "/auth-entry.mjs?v=1.24.0",
    "/auth-product.mjs?v=1.24.0",
    "/authenticated-public-read.mjs?v=1.24.0",
    "/authenticated-public-write.mjs?v=1.24.0",
    "/nostr-event-verifier.mjs?v=1.24.0",
    "/components.mjs?v=1.24.0",
    "/shell.mjs?v=1.24.0"
  ]) {
    const result = await invoke(handler, { url: path });
    assert.equal(result.statusCode, 200, path);
  }

  for (const path of [
    "/auth-entry.mjs?",
    "/auth-entry.mjs?v=1.18",
    "/auth-entry.mjs?v=1.24.0&extra=1",
    "/demo.html?v=1.24.0"
  ]) {
    const result = await invoke(handler, { url: path });
    assert.equal(result.statusCode, 400, path);
  }
});

test("Limited rehearsal completes login callback session authority and logout", async () => {
  const {
    runtime,
    handler,
    sessionCookie
  } = await authenticatedFlow("limited");

  const logout = await invoke(handler, {
    url: "/auth/logout",
    method: "POST",
    headers: {
      cookie: sessionCookie,
      origin: runtime.config.publicOrigin,
      "content-length": "0"
    },
    rawHeaders: [
      "Content-Length",
      "0"
    ]
  });

  assert.equal(logout.statusCode, 200);
  assert.deepEqual(jsonBody(logout), {
    authenticated: false
  });

  const after = await invoke(handler, {
    url: "/auth/session",
    headers: {
      cookie: sessionCookie
    }
  });

  assert.deepEqual(jsonBody(after), {
    authenticated: false
  });
});

test("Full rehearsal projects Full only for the authenticated fixed subject", async () => {
  const {
    handler,
    sessionCookie
  } = await authenticatedFlow("full");

  const authority = await invoke(handler, {
    url: "/auth/authority",
    headers: {
      cookie: sessionCookie
    }
  });

  assert.deepEqual(jsonBody(authority), {
    subject: REHEARSAL_SUBJECT,
    status: "full",
    valid: true
  });
});

test("caller cannot supply or replace the authenticated authority subject", async () => {
  const {
    handler,
    sessionCookie
  } = await authenticatedFlow("full");

  const attempted = await invoke(handler, {
    url: `/auth/authority?subject=${"0".repeat(64)}`,
    headers: {
      cookie: sessionCookie
    }
  });

  assert.equal(attempted.statusCode, 400);
  assert.deepEqual(jsonBody(attempted), {
    error: "request_rejected"
  });

  const unchanged = await invoke(handler, {
    url: "/auth/session",
    headers: {
      cookie: sessionCookie
    }
  });

  assert.deepEqual(jsonBody(unchanged), {
    authenticated: true,
    subject: REHEARSAL_SUBJECT
  });
});
