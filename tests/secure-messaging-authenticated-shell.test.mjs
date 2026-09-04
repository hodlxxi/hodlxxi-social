import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  buildSecureMessagingRecipients,
  loadSecureMessagingSnapshot,
  parseSecureMessagingDirectoryDocument,
  parseSecureMessagingSessionDocument,
  renderSecureMessagingAuthenticatedShell
} from "../web/secure-messaging-v128.mjs";

const subject = "a".repeat(64);
const directory = Object.freeze({
  state: "available",
  participants: Object.freeze([
    Object.freeze({ alias: "pairwise.member-1" }),
    Object.freeze({ alias: "pairwise.member-2" })
  ])
});

const response = (document) => ({
  status: 200,
  headers: {
    get(name) {
      return name.toLowerCase() === "content-type"
        ? "application/json"
        : null;
    }
  },
  async text() {
    return JSON.stringify(document);
  }
});

test("V1.28B accepts only canonical session subject and viewer-private directory aliases", () => {
  assert.deepEqual(
    parseSecureMessagingSessionDocument({
      authenticated: true,
      subject
    }),
    { authenticated: true, subject }
  );

  assert.deepEqual(
    parseSecureMessagingDirectoryDocument(directory),
    directory
  );

  for (const unsafe of [
    "b".repeat(64),
    "npub1example",
    "nsec1example",
    "xpubExample",
    "bc1example",
    "person@example.com",
    "15551234567"
  ]) {
    assert.throws(
      () => parseSecureMessagingDirectoryDocument({
        state: "available",
        participants: [{ alias: unsafe }]
      }),
      /invalid secure messaging directory/
    );
  }
});

test("V1.28B reads private labels locally and preserves opaque alias identity", () => {
  const reads = [];
  const recipients = buildSecureMessagingRecipients({
    subject,
    directory,
    labelStore: {
      read(input) {
        reads.push(input);
        return input.alias === "pairwise.member-1"
          ? "Brother"
          : null;
      }
    }
  });

  assert.deepEqual(recipients, [
    { alias: "pairwise.member-1", label: "Brother" },
    { alias: "pairwise.member-2", label: null }
  ]);
  assert.deepEqual(reads, [
    { subject, alias: "pairwise.member-1" },
    { subject, alias: "pairwise.member-2" }
  ]);
});

test("Limited V1.28B fails closed before any session or directory network read", async () => {
  const calls = [];
  const snapshot = await loadSecureMessagingSnapshot({
    access: "limited",
    fetchImpl: async (...args) => {
      calls.push(args);
      throw new Error("must not call network");
    },
    labelStore: { read: () => null }
  });

  assert.deepEqual(snapshot, {
    state: "restricted",
    recipients: []
  });
  assert.equal(calls.length, 0);
});

test("Full V1.28B uses only same-origin session and Full Directory reads", async () => {
  const calls = [];
  const snapshot = await loadSecureMessagingSnapshot({
    access: "full",
    fetchImpl: async (url, options) => {
      calls.push([url, options]);
      if (url === "/auth/session") {
        return response({ authenticated: true, subject });
      }
      if (url === "/auth/full-directory") {
        return response(directory);
      }
      throw new Error(`unexpected URL: ${url}`);
    },
    labelStore: {
      read({ alias }) {
        return alias === "pairwise.member-1"
          ? "Brother"
          : null;
      }
    }
  });

  assert.equal(snapshot.state, "available");
  assert.deepEqual(snapshot.recipients, [
    { alias: "pairwise.member-1", label: "Brother" },
    { alias: "pairwise.member-2", label: null }
  ]);
  assert.deepEqual(calls.map(([url]) => url), [
    "/auth/session",
    "/auth/full-directory"
  ]);
  assert.ok(calls.every(([, options]) =>
    options.credentials === "same-origin" &&
    options.method === "GET" &&
    options.cache === "no-store" &&
    options.redirect === "error"
  ));
});

test("V1.28B render exposes private labels and aliases but no raw identity or active send path", () => {
  const html = renderSecureMessagingAuthenticatedShell({
    state: "available",
    recipients: [
      { alias: "pairwise.member-1", label: "Brother" },
      { alias: "pairwise.member-2", label: null }
    ]
  }, {
    selectedAlias: "pairwise.member-1"
  });

  assert.match(html, /Messages/);
  assert.match(html, /Brother/);
  assert.match(html, /pairwise\.member-1/);
  assert.match(html, /Current Full member/);
  assert.match(html, /V1\.28B selection only/);
  assert.match(html, /Transport disabled in V1\.28B/);
  assert.match(html, /textarea[^>]+disabled/);
  assert.match(html, /button type="submit" disabled/);
  assert.doesNotMatch(html, new RegExp(subject));
  assert.doesNotMatch(
    html,
    /npub1|nsec1|xpub|x25519|bitcoin address|email|phone/i
  );
});

test("V1.28B repository-facing additions are English-only and contain no crypto, capability issuance, message transport, or persistence implementation", async () => {
  const paths = [
    "../web/secure-messaging-v128.mjs",
    "../web/secure-messaging-v128.css",
    "../prototypes/secure-messaging/index.html",
    "../prototypes/secure-messaging/preview.mjs",
    "../prototypes/secure-messaging/prototype.mjs",
    "../prototypes/secure-messaging/preview.css",
    "../docs/SECURE_MESSAGING_V1_28_ARCHITECTURE.md"
  ];

  const source = (await Promise.all(paths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8")
  ))).join("\n");

  assert.doesNotMatch(source, /[\u0400-\u04ff]/u);

  const implementation = await readFile(
    new URL("../web/secure-messaging-v128.mjs", import.meta.url),
    "utf8"
  );

  for (const forbidden of [
    /crypto\.subtle/,
    /generateKey\s*\(/,
    /deriveKey\s*\(/,
    /encrypt\s*\(/,
    /decrypt\s*\(/,
    /WebSocket\s*\(/,
    /window\.nostr/,
    /\/auth\/recipient-capability/,
    /\/api\/messages\//,
    /localStorage\.(?:setItem|removeItem)/,
    /indexedDB/i,
    /XMLHttpRequest/
  ]) {
    assert.doesNotMatch(implementation, forbidden);
  }
});

test("authenticated entry is the sole production owner of the V1.28B Messages route", async () => {
  const html = await readFile(
    new URL("../web/index.html", import.meta.url),
    "utf8"
  );
  const entry = await readFile(
    new URL("../web/auth-entry.mjs", import.meta.url),
    "utf8"
  );
  const product = await readFile(
    new URL("../web/auth-product.mjs", import.meta.url),
    "utf8"
  );
  const messaging = await readFile(
    new URL("../web/secure-messaging-v128.mjs", import.meta.url),
    "utf8"
  );

  assert.match(html, /styles\.css\?v=1\.28\.1/);
  assert.match(html, /secure-messaging-v128\.css\?v=1\.28\.1/);
  assert.match(html, /auth-entry\.mjs\?v=1\.28\.1/);
  assert.doesNotMatch(
    html,
    /<script[^>]+src="\.\/secure-messaging-v128\.mjs/
  );
  assert.match(entry, /auth-product\.mjs\?v=1\.28\.1/);
  assert.match(product, /renderSecureMessagingAuthenticatedShell/);
  assert.doesNotMatch(
    messaging,
    /if \(typeof document !== "undefined"\)/
  );
});
