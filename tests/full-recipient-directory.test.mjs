import assert from "node:assert/strict";
import test from "node:test";
import {
  FULL_RECIPIENT_DIRECTORY_SCHEMA,
  FULL_RECIPIENT_DIRECTORY_UNAVAILABLE,
  MAX_FULL_DIRECTORY_FRESHNESS_MS,
  normalizeFullRecipientDirectory
} from "../src/full-recipient-directory.mjs";
import { MAX_PROTECTED_RECIPIENTS } from "../src/protected-content.mjs";

const now = 1_700_000_000_000;
const subjectA = "a".repeat(64);
const subjectB = "b".repeat(64);
const keyA = `${"c".repeat(62)}44`;
const keyB = `${"d".repeat(62)}55`;
const snapshotId = "snapshot:synthetic:1";

const recipient = (subject = subjectA, publicKey = keyA, patch = {}) => ({
  snapshotId,
  subject,
  encryptionKey: { algorithm: "x25519-v1", version: 1, publicKey, validFrom: now - 1, expiresAt: now + 1, revoked: false },
  authority: { source: "hodlxxi-crt", version: 1, snapshotId, subject, status: "full", expiresAt: now + 1 },
  ...patch
});

const directory = (recipients = [recipient()], patch = {}) => ({
  schema: FULL_RECIPIENT_DIRECTORY_SCHEMA,
  version: 1,
  source: "hodlxxi-crt",
  snapshotId,
  complete: true,
  issuedAt: now - 1,
  expiresAt: now + 1,
  recipients,
  ...patch
});

test("accepts one exact complete authoritative snapshot and returns immutable canonical bindings", () => {
  const result = normalizeFullRecipientDirectory(directory([recipient(subjectA, keyA), recipient(subjectB, keyB)]), { now });
  assert.equal(result.state, "available");
  assert.equal(result.snapshotId, snapshotId);
  assert.deepEqual(result.recipients.map(({ subject }) => subject), [subjectA, subjectB]);
  assert.deepEqual(result.recipients[0].encryptionKey, {
    algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now - 1, expiresAt: now + 1
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.recipients));
  assert.ok(Object.isFrozen(result.recipients[0]));
  assert.ok(Object.isFrozen(result.recipients[0].encryptionKey));
});

test("an empty complete directory is available and distinct from unavailable", () => {
  const result = normalizeFullRecipientDirectory(directory([]), { now });
  assert.deepEqual(result, { state: "available", snapshotId, recipients: [] });
  assert.notStrictEqual(result, FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
});

test("all malformed or non-authoritative snapshots return the same generic result", () => {
  const getter = {};
  Object.defineProperty(getter, "schema", { enumerable: true, get() { throw new Error("must not run"); } });
  const inherited = Object.create(directory());
  const cases = [
    undefined, null, [], getter, inherited,
    directory([], { schema: "unknown" }),
    directory([], { version: 2 }),
    directory([], { source: "nostr" }),
    directory([], { snapshotId: "" }),
    directory([], { complete: false }),
    { ...directory([]), extra: true }
  ];
  for (const value of cases) assert.strictEqual(normalizeFullRecipientDirectory(value, { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  assert.deepEqual(FULL_RECIPIENT_DIRECTORY_UNAVAILABLE, { state: "unavailable" });
  assert.ok(Object.isFrozen(FULL_RECIPIENT_DIRECTORY_UNAVAILABLE));
});

test("recipient arrays must be ordinary dense data arrays and never execute accessors", () => {
  let calls = 0;
  const accessorArray = [];
  Object.defineProperty(accessorArray, "0", { enumerable: true, get() { calls += 1; throw new Error("must not run"); } });
  const iteratorArray = [recipient()];
  Object.defineProperty(iteratorArray, Symbol.iterator, { value() { calls += 1; throw new Error("must not run"); } });
  const sparseArray = new Array(1);
  for (const recipients of [accessorArray, iteratorArray, sparseArray]) {
    assert.strictEqual(normalizeFullRecipientDirectory(directory(recipients), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  }
  assert.equal(calls, 0);
});

test("snapshot issuance freshness expiry and caller bounds fail closed", () => {
  const cases = [
    [directory([], { issuedAt: now + 1 }), { now }],
    [directory([], { expiresAt: now }), { now }],
    [directory([], { issuedAt: now, expiresAt: now }), { now }],
    [directory([], { issuedAt: now - MAX_FULL_DIRECTORY_FRESHNESS_MS, expiresAt: now + 1 }), { now }],
    [directory([]), { now: Number.NaN }],
    [directory([]), { now, limit: 0 }],
    [directory([]), { now, limit: MAX_PROTECTED_RECIPIENTS + 1 }]
  ];
  for (const [value, options] of cases) assert.strictEqual(normalizeFullRecipientDirectory(value, options), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
});

test("recipient count ordering subjects and encryption bindings are unambiguous", () => {
  const repeated = Array.from({ length: MAX_PROTECTED_RECIPIENTS + 1 }, () => recipient());
  for (const recipients of [
    repeated,
    [recipient(subjectB, keyB), recipient(subjectA, keyA)],
    [recipient(subjectA, keyA), recipient(subjectA, keyB)],
    [recipient(subjectA, keyA), recipient(subjectB, keyA)],
    [recipient(subjectA, keyA), recipient(subjectB, keyB, { encryptionKey: { ...recipient(subjectB, keyA).encryptionKey, version: 2 } })],
    [recipient(subjectA, subjectA)],
    [recipient(subjectA.toUpperCase(), keyA)]
  ]) assert.strictEqual(normalizeFullRecipientDirectory(directory(recipients), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
});

test("encryption key lifecycle algorithm and version are explicit", () => {
  const badKeys = [
    { algorithm: "secp256k1-signing", version: 1, publicKey: keyA, validFrom: now - 1, expiresAt: now + 1, revoked: false },
    { algorithm: "x25519-v1", version: 0, publicKey: keyA, validFrom: now - 1, expiresAt: now + 1, revoked: false },
    { algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now + 1, expiresAt: now + 2, revoked: false },
    { algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now - 1, expiresAt: now, revoked: false },
    { algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now - 2, expiresAt: now + 1, revoked: false },
    { algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now - 1, expiresAt: now + 2, revoked: false },
    { algorithm: "x25519-v1", version: 1, publicKey: keyA, validFrom: now - 1, expiresAt: now + 1, revoked: true }
  ];
  for (const encryptionKey of badKeys) {
    assert.strictEqual(normalizeFullRecipientDirectory(directory([recipient(subjectA, keyA, { encryptionKey })]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  }
});

test("prohibited low-order X25519 encodings are not encryption-capable bindings", () => {
  const prohibited = [
    "00".repeat(32),
    `01${"00".repeat(31)}`,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098c9d770ad86a4aa59bf9814b4d00",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    `ec${"ff".repeat(30)}7f`,
    `ed${"ff".repeat(30)}7f`,
    `ee${"ff".repeat(30)}7f`
  ];
  const highBitAlias = (publicKey) => `${publicKey.slice(0, 62)}${(Number.parseInt(publicKey.slice(62), 16) | 0x80).toString(16).padStart(2, "0")}`;
  for (const publicKey of [...prohibited, ...prohibited.map(highBitAlias)]) {
    assert.strictEqual(normalizeFullRecipientDirectory(directory([recipient(subjectA, publicKey)]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  }
});

test("every recipient requires same-snapshot exact-subject current external Full authority", () => {
  const badAuthorities = [
    { source: "hodlxxi-crt", version: 1, snapshotId, subject: subjectA, status: "limited", expiresAt: now + 1 },
    { source: "hodlxxi-crt", version: 1, snapshotId, subject: subjectA, status: "operator", expiresAt: now + 1 },
    { source: "nostr", version: 1, snapshotId, subject: subjectA, status: "full", expiresAt: now + 1 },
    { source: "hodlxxi-crt", version: 2, snapshotId, subject: subjectA, status: "full", expiresAt: now + 1 },
    { source: "hodlxxi-crt", version: 1, snapshotId: "snapshot:other", subject: subjectA, status: "full", expiresAt: now + 1 },
    { source: "hodlxxi-crt", version: 1, snapshotId, subject: subjectB, status: "full", expiresAt: now + 1 },
    { source: "hodlxxi-crt", version: 1, snapshotId, subject: subjectA, status: "full", expiresAt: now }
  ];
  for (const authority of badAuthorities) {
    assert.strictEqual(normalizeFullRecipientDirectory(directory([recipient(subjectA, keyA, { authority })]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  }
  for (const substitute of [{ friend: true }, { sponsorTrust: true }, { kind: 0 }, { source: "synthetic" }]) {
    assert.strictEqual(normalizeFullRecipientDirectory(directory([recipient(subjectA, keyA, { authority: substitute })]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  }
});

test("mixed snapshot recipient records and unsupported fields fail closed", () => {
  assert.strictEqual(normalizeFullRecipientDirectory(directory([recipient(subjectA, keyA, { snapshotId: "snapshot:other" })]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  assert.strictEqual(normalizeFullRecipientDirectory(directory([{ ...recipient(), plaintext: "secret" }]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
  assert.strictEqual(normalizeFullRecipientDirectory(directory([{ ...recipient(), encryptionKey: { ...recipient().encryptionKey, signing: true } }]), { now }), FULL_RECIPIENT_DIRECTORY_UNAVAILABLE);
});
