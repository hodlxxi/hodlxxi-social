import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_PROTECTED_RECIPIENTS,
  FULL_NETWORK,
  PUBLIC,
  PROTECTED_ENVELOPE_SCHEMA,
  PROTECTED_PAYLOAD_SCHEMA,
  PROTECTED_READ_DENIED,
  ProtectedAudience,
  defineProtectedContentDependencies,
  normalizeCurrentFullRecipients,
  normalizeProtectedEnvelope,
  normalizeProtectedPayload,
  protectedReadDecision,
  protectedReadResult,
  protectedWriteDecision,
  resolveProtectedRecipients
} from "../src/protected-content.mjs";

const now = 1_700_000_000_000;
const alice = "a".repeat(64);
const bob = "b".repeat(64);
const full = (subject = alice, patch = {}) => ({ source: "hodlxxi-crt", version: 1, subject, status: "full", expiresAt: now + 1, ...patch });

test("canonical audiences and decisions are immutable", () => {
  assert.equal(PUBLIC, "PUBLIC");
  assert.equal(FULL_NETWORK, "FULL_NETWORK");
  assert.deepEqual(ProtectedAudience, { PUBLIC: "PUBLIC", FULL_NETWORK: "FULL_NETWORK" });
  assert.ok(Object.isFrozen(ProtectedAudience));
  assert.deepEqual(protectedWriteDecision({ audience: "PUBLIC" }), { allowed: true, reason: "public" });
  assert.deepEqual(protectedReadDecision({ audience: "PUBLIC" }), { allowed: true, reason: "public" });
  assert.ok(Object.isFrozen(protectedWriteDecision({ audience: "PUBLIC" })));
});

test("current exact Full author and reader are independently authorized", () => {
  const input = { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(), now };
  assert.deepEqual(protectedWriteDecision(input), { allowed: true, reason: "current-full" });
  assert.deepEqual(protectedReadDecision(input), { allowed: true, reason: "current-full" });
});

test("protected decisions fail closed for authority failures", () => {
  const accessor = {};
  Object.defineProperty(accessor, "source", { enumerable: true, get() { throw new Error("must not run"); } });
  const denied = [
    {},
    { audience: "FRIENDS", authenticatedSubject: alice, assertion: full(), now },
    { audience: "full_network", authenticatedSubject: alice, assertion: full(), now },
    { audience: "FULL_NETWORK", assertion: full(), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice.toUpperCase(), assertion: full(), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(bob), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { status: "limited" }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { status: "operator" }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { expiresAt: now }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { source: "nostr" }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { version: 2 }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { evidenceRef: "" }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(alice, { evidenceRef: 7 }), now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: { ...full(), callerStatus: "full" }, now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: accessor, now },
    { audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: new Proxy({}, { getPrototypeOf() { throw new Error("must not escape"); } }), now }
  ];
  for (const input of denied) {
    assert.equal(protectedWriteDecision(input).allowed, false);
    assert.equal(protectedReadDecision(input).allowed, false);
  }
});

test("malformed hostile top-level inputs return fixed denials", () => {
  const getter = {};
  Object.defineProperty(getter, "audience", { enumerable: true, get() { throw new Error("must not run"); } });
  const proxy = new Proxy({}, { getPrototypeOf() { throw new Error("must not escape"); } });
  for (const input of [null, getter, proxy]) {
    assert.strictEqual(protectedWriteDecision(input), protectedWriteDecision(null));
    assert.strictEqual(protectedReadDecision(input), protectedReadDecision(null));
    assert.deepEqual(protectedReadDecision(input), { allowed: false, reason: "unsupported-audience" });
  }
});

test("friendship sponsor Nostr and synthetic claims cannot grant access", () => {
  for (const assertion of [
    { friend: true, status: "full" },
    { sponsorTrust: true, status: "full" },
    { kind: 0, pubkey: alice, content: JSON.stringify({ status: "full" }) },
    { source: "synthetic", subject: alice, status: "full", expiresAt: now + 1 }
  ]) assert.equal(protectedReadDecision({ audience: "FULL_NETWORK", authenticatedSubject: alice, assertion, now }).allowed, false);
});

test("all denied reads return the same metadata-free result", () => {
  const denied = protectedReadDecision({ audience: "FULL_NETWORK", authenticatedSubject: alice, assertion: full(bob), now });
  const first = protectedReadResult(denied, [{ authorId: alice, timestamp: now }]);
  const second = protectedReadResult({ allowed: false, reason: "anything" }, [{ id: "exists", recipients: [alice] }]);
  assert.strictEqual(first, PROTECTED_READ_DENIED);
  assert.strictEqual(second, PROTECTED_READ_DENIED);
  assert.deepEqual(Object.keys(first), ["state", "items"]);
  assert.deepEqual(first, { state: "denied", items: [] });
  assert.ok(Object.isFrozen(first.items));
});

test("authoritative recipient sets require bounded unique current Full assertions", () => {
  assert.deepEqual(normalizeCurrentFullRecipients([full(bob), full(alice)], { now }), [alice, bob]);
  assert.equal(normalizeCurrentFullRecipients([full(alice), full(alice)], { now }), undefined);
  assert.equal(normalizeCurrentFullRecipients([full(alice, { status: "limited" })], { now }), undefined);
  assert.equal(normalizeCurrentFullRecipients([full(alice, { expiresAt: now })], { now }), undefined);
  assert.equal(normalizeCurrentFullRecipients([full(alice)], { now, limit: 0 }), undefined);
  assert.equal(normalizeCurrentFullRecipients(new Array(MAX_PROTECTED_RECIPIENTS + 1).fill(full()), { now }), undefined);
});

test("protected envelope shape is opaque and rejects public Nostr and plaintext fields", () => {
  const raw = { schema: PROTECTED_ENVELOPE_SCHEMA, version: 1, opaquePayload: "implementation-defined" };
  assert.deepEqual(normalizeProtectedEnvelope(raw), raw);
  assert.ok(Object.isFrozen(normalizeProtectedEnvelope(raw)));
  assert.equal(normalizeProtectedEnvelope({ ...raw, plaintext: "secret" }), undefined);
  assert.equal(normalizeProtectedEnvelope({ kind: 1, pubkey: alice, content: "secret", id: "x", sig: "y", tags: [], created_at: 1 }), undefined);
  assert.equal(normalizeProtectedEnvelope({ kind: 0, content: "{}" }), undefined);
  const payload = { schema: PROTECTED_PAYLOAD_SCHEMA, version: 1, opaqueContent: "implementation-defined" };
  assert.deepEqual(normalizeProtectedPayload(payload), payload);
  assert.equal(normalizeProtectedPayload({ ...payload, plaintext: "secret" }), undefined);
  assert.equal(normalizeProtectedPayload({ kind: 1, content: "secret" }), undefined);
});

test("dependency boundary accepts contracts only and rejects missing operations", async () => {
  const recipientResolver = { resolveCurrentFull() {} };
  const rawEnvelope = { schema: PROTECTED_ENVELOPE_SCHEMA, version: 1, opaquePayload: "sealed" };
  const rawPayload = { schema: PROTECTED_PAYLOAD_SCHEMA, version: 1, opaqueContent: "opaque" };
  const transport = { putEnvelope: () => true, getEnvelope: () => rawEnvelope };
  const envelope = { produceEnvelope: () => rawEnvelope, openEnvelope: () => rawPayload };
  const dependencies = defineProtectedContentDependencies({ recipientResolver, transport, envelope });
  assert.deepEqual(Object.keys(dependencies), ["recipientResolver", "transport", "envelope"]);
  assert.ok(Object.isFrozen(dependencies));
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver, transport, envelope: {} }), /protected envelope dependency required/);
  assert.equal(await dependencies.transport.putEnvelope("post:1", rawEnvelope), true);
  assert.deepEqual(await dependencies.transport.getEnvelope("post:1"), rawEnvelope);
  assert.deepEqual(await dependencies.envelope.produceEnvelope(rawPayload, [alice]), rawEnvelope);
  assert.deepEqual(await dependencies.envelope.openEnvelope(rawEnvelope, alice), rawPayload);
});

test("dependency contracts reject extra capabilities and accessors", () => {
  const resolver = { resolveCurrentFull() {} };
  const transport = { putEnvelope() {}, getEnvelope() {} };
  const envelope = { produceEnvelope() {}, openEnvelope() {} };
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver: { ...resolver, grantFull() {} }, transport, envelope }), /protected recipient resolver required/);
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver: resolver, transport: { ...transport, plaintext() {} }, envelope }), /protected envelope transport required/);
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver: resolver, transport, envelope: { ...envelope, sign() {} } }), /protected envelope dependency required/);
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver: resolver, transport, envelope, signer() {} }), /protected recipient resolver required/);
  const hostile = {};
  Object.defineProperty(hostile, "resolveCurrentFull", { enumerable: true, get() { throw new Error("must not run"); } });
  assert.throws(() => defineProtectedContentDependencies({ recipientResolver: hostile, transport, envelope }), /protected recipient resolver required/);
});

test("every dependency seam rejects plaintext and public Nostr records", async () => {
  const publicEvent = { kind: 1, pubkey: alice, content: "secret", id: "x", sig: "y", tags: [], created_at: 1 };
  const plaintext = { plaintext: "secret" };
  const recipientResolver = { resolveCurrentFull() {} };
  for (const bad of [publicEvent, plaintext]) {
    const dependencies = defineProtectedContentDependencies({
      recipientResolver,
      transport: { putEnvelope: () => true, getEnvelope: () => bad },
      envelope: { produceEnvelope: () => bad, openEnvelope: () => bad }
    });
    await assert.rejects(dependencies.transport.putEnvelope("post:1", bad), /opaque protected envelope required/);
    assert.equal(await dependencies.transport.getEnvelope("post:1"), undefined);
    await assert.rejects(dependencies.envelope.produceEnvelope(bad, [alice]), /opaque protected payload required/);
    assert.equal(await dependencies.envelope.produceEnvelope({ schema: PROTECTED_PAYLOAD_SCHEMA, version: 1, opaqueContent: "opaque" }, [alice]), undefined);
    assert.equal(await dependencies.envelope.openEnvelope({ schema: PROTECTED_ENVELOPE_SCHEMA, version: 1, opaquePayload: "sealed" }, alice), undefined);
  }
});

test("recipient resolver seam bounds and validates authoritative output", async () => {
  const transport = { putEnvelope() {}, getEnvelope() {} };
  const envelope = { produceEnvelope() {}, openEnvelope() {} };
  const accepted = defineProtectedContentDependencies({ recipientResolver: { resolveCurrentFull: () => [full(bob), full(alice)] }, transport, envelope });
  assert.deepEqual(await resolveProtectedRecipients(accepted, { now, limit: 2 }), [alice, bob]);
  const unavailable = defineProtectedContentDependencies({ recipientResolver: { resolveCurrentFull() { throw new Error("offline"); } }, transport, envelope });
  assert.equal(await resolveProtectedRecipients(unavailable, { now }), undefined);
  const excessive = defineProtectedContentDependencies({ recipientResolver: { resolveCurrentFull: () => [full(alice), full(bob)] }, transport, envelope });
  assert.equal(await resolveProtectedRecipients(excessive, { now, limit: 1 }), undefined);
});
