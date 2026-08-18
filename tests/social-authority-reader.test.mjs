import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createSocialAuthorityReader } from "../src/server/social-authority-reader.mjs";

const subject = "c".repeat(64);

const config = Object.freeze({
  authorityOrigin: "https://authority.example",
  outboundTimeoutMs: 5000
});

const raw = (identityClass = "limited", overrides = {}) => ({
  current_full_relation_satisfied: identityClass === "full",
  evidence_source: `${identityClass}-evidence`,
  identity_class: identityClass,
  observed_at:
    identityClass === "full"
      ? "2026-08-12T10:11:12+00:00"
      : null,
  schema: "hodlxxi.current_entitlement_assertion.v1",
  subject,
  valid: true,
  ...overrides
});

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });

const dependencies = (fetchImpl) => ({
  fetchImpl,
  setTimeoutImpl: () => 1,
  clearTimeoutImpl() {},
  AbortControllerImpl: AbortController
});

test("server reader reuses the existing authority composition for exact Limited and Full", async () => {
  for (const identityClass of ["limited", "full"]) {
    const calls = [];

    const reader = createSocialAuthorityReader(
      config,
      dependencies(async (...args) => {
        calls.push(args);
        return jsonResponse(raw(identityClass));
      })
    );

    const result = await reader(subject);

    assert.deepEqual(result, {
      subject,
      status: identityClass,
      valid: true
    });

    assert.equal(calls.length, 1);
    assert.equal(
      calls[0][0],
      `https://authority.example/agent/authority/current/${subject}.json`
    );

    assert.equal(calls[0][1].method, "GET");
    assert.equal(calls[0][1].credentials, "omit");
    assert.equal(calls[0][1].redirect, "manual");
  }
});

test("denied and unavailable authority fail closed to Limited", async () => {
  for (const [status, body] of [
    [404, { error: "entitlement_denied" }],
    [503, { error: "entitlement_unavailable" }],
    [400, { error: "invalid_subject" }]
  ]) {
    const reader = createSocialAuthorityReader(
      config,
      dependencies(async () => jsonResponse(body, status))
    );

    assert.deepEqual(await reader(subject), {
      subject,
      status: "limited",
      valid: false
    });
  }
});

test("malformed mismatch and Operator responses cannot elevate", async () => {
  for (const body of [
    raw("operator"),
    raw("full", { subject: "d".repeat(64) }),
    raw("full", { valid: false }),
    { unexpected: "shape" }
  ]) {
    const reader = createSocialAuthorityReader(
      config,
      dependencies(async () => jsonResponse(body))
    );

    assert.deepEqual(await reader(subject), {
      subject,
      status: "limited",
      valid: false
    });
  }
});

test("production reader is an inert bridge to the existing authority pipeline", async () => {
  const [readerSource, serverSource, browserSource] = await Promise.all([
    readFile(
      new URL("../src/server/social-authority-reader.mjs", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../scripts/hodlxxi-social-server.mjs", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../web/auth-entry.mjs", import.meta.url),
      "utf8"
    )
  ]);

  assert.match(readerSource, /runSocialAuthorityComposition/);
  assert.match(readerSource, /formatSocialAuthorityResult/);

  assert.match(serverSource, /createSocialAuthorityReader\(config\)/);
  assert.match(serverSource, /authorityReader/);

  assert.doesNotMatch(
    readerSource,
    /agent\/authority\/current/
  );

  assert.doesNotMatch(
    browserSource,
    /agent\/authority\/current|authorityOrigin|hodlxxi\.com/i
  );

  assert.doesNotMatch(
    readerSource + serverSource,
    /setInterval|localStorage|sessionStorage|indexedDB|private.?key|publish\(|sign\w*\(/i
  );
});
