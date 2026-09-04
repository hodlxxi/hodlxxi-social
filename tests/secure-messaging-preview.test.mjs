import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import {
  normalizeSecureMessagingPreview,
  renderSecureMessagingPreview
} from "../prototypes/secure-messaging/preview.mjs";

const fixture = () => ({
  device: {
    label: "This browser - MacBook",
    state: "ready"
  },
  conversations: [
    {
      id: "conversation-1",
      person: {
        alias: "p_safeAliasOne",
        label: "Brother",
        status: "full"
      },
      timestamp: "18:22",
      unread: 1,
      messages: [
        {
          direction: "outgoing",
          body: "Encrypted preview message",
          time: "18:21",
          state: "opened"
        }
      ]
    }
  ],
  recipientCandidates: [
    {
      alias: "p_safeAliasOne",
      label: "Brother",
      status: "full"
    }
  ],
  selectedConversationId: "conversation-1"
});

test("secure messaging preview accepts only Full viewer-private aliases", () => {
  const model = normalizeSecureMessagingPreview(fixture());
  assert.equal(model.conversations[0].person.status, "full");
  assert.equal(model.conversations[0].person.alias, "p_safeAliasOne");

  for (const unsafe of [
    "a".repeat(64),
    "npub1example",
    "xpubExample",
    "bc1example",
    "person@example.com",
    "15551234567"
  ]) {
    const invalid = fixture();
    invalid.recipientCandidates[0].alias = unsafe;
    assert.throws(
      () => normalizeSecureMessagingPreview(invalid),
      /invalid secure messaging preview person/
    );
  }
});

test("secure messaging preview rejects Limited recipients and unknown conversations", () => {
  const limited = fixture();
  limited.recipientCandidates[0].status = "limited";
  assert.throws(
    () => normalizeSecureMessagingPreview(limited),
    /invalid secure messaging preview person/
  );

  const missing = fixture();
  missing.selectedConversationId = "unknown";
  assert.throws(
    () => normalizeSecureMessagingPreview(missing),
    /unknown selected conversation/
  );
});

test("secure messaging preview renders privacy and inertness disclosures", () => {
  const html = renderSecureMessagingPreview(fixture());
  assert.match(html, /V1\.28 UX preview/);
  assert.match(html, /No network · no crypto · no persistence · no production wiring/);
  assert.match(html, /End-to-end encrypted/);
  assert.match(html, /ciphertext only/i);
  assert.match(html, /Private device keys and plaintext stay on user devices/i);
  assert.match(html, /Nostr optional/);
  assert.match(html, /V1\.27 → rc_… → V1\.28 crypto package/);
});

test("secure messaging preview escapes private labels and message text", () => {
  const malicious = fixture();
  malicious.conversations[0].person.label = "<b>Brother</b>";
  malicious.recipientCandidates[0].label = "<b>Brother</b>";
  malicious.conversations[0].messages[0].body = "<script>alert(1)</script>";

  const html = renderSecureMessagingPreview(malicious);
  assert.doesNotMatch(html, /<script>/);
  assert.doesNotMatch(html, /<b>Brother<\/b>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;b&gt;Brother&lt;\/b&gt;/);
});

test("prototype source contains no network crypto persistence or production integration path", () => {
  const source = [
    fs.readFileSync(new URL("../prototypes/secure-messaging/preview.mjs", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../prototypes/secure-messaging/prototype.mjs", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../prototypes/secure-messaging/index.html", import.meta.url), "utf8")
  ].join("\n");

  for (const forbidden of [
    /\bfetch\s*\(/,
    /WebSocket\s*\(/,
    /localStorage/,
    /sessionStorage/,
    /indexedDB/i,
    /crypto\.subtle/,
    /generateKey\s*\(/,
    /window\.nostr/,
    /\/auth\/recipient-capability/,
    /\/api\/messages\//
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

test("V1.28 repository-facing prototype files contain no Cyrillic text", () => {
  const files = [
    "../docs/SECURE_MESSAGING_V1_28_ARCHITECTURE.md",
    "../prototypes/secure-messaging/index.html",
    "../prototypes/secure-messaging/preview.css",
    "../prototypes/secure-messaging/preview.mjs",
    "../prototypes/secure-messaging/prototype.mjs",
    "./secure-messaging-preview.test.mjs"
  ];

  for (const relativePath of files) {
    const source = fs.readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(source, /[\u0400-\u04FF]/u);
  }
});
