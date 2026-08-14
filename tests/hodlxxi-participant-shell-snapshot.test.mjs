import test from "node:test";
import assert from "node:assert/strict";
import { SOCIAL_AUTHORITY_PROJECTION_SCHEMA } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { createParticipantShellSnapshot } from "../src/dev/hodlxxi-participant-shell-snapshot.mjs";

const subject = "a".repeat(64);
const authority = (status = "full", overrides = {}) => Object.freeze({ schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass: status, valid: true, diagnostic: "asserted", evidenceSource: "bounded-evidence", observedAt: status === "full" ? "2026-08-14T00:00:00+00:00" : null, ...overrides });
const result = (overrides = {}) => ({ subject, noteLimit: 3, authority: { status: "fulfilled", value: authority() }, profile: { status: "fulfilled", value: { id: subject, publicKey: subject, displayName: "Ada" } }, notes: { status: "fulfilled", value: [{ id: "n1", authorId: subject, audience: "PUBLIC", body: "hello", timestamp: "now", reactions: 0, comments: 0, reposts: 0, replies: [] }] }, ...overrides });

test("creates one deeply immutable exact-subject renderer snapshot without fabricated graph", () => {
  const snapshot = createParticipantShellSnapshot(result());
  assert.equal(snapshot.currentViewerId, subject);
  assert.deepEqual(snapshot.participants, [{ id: subject, publicKey: subject, displayName: "Ada" }]);
  assert.equal(snapshot.profileAvailable, true);
  assert.equal(snapshot.statuses[subject], "full");
  assert.deepEqual(snapshot.externalAssertions[subject], { subject, assertedStatus: "full", source: "hodlxxi-authority-probe", valid: true, evidenceRef: "bounded-evidence" });
  for (const key of ["edges", "friendEdges", "sponsorTrustEdges", "groups", "conversations", "messages", "notifications"]) assert.deepEqual(snapshot[key], []);
  assert.equal(snapshot.notes.length, 1);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.participants), true);
  assert.equal(Object.isFrozen(snapshot.notes[0].replies), true);
  assert.throws(() => snapshot.notes.push({}), TypeError);
});

test("authority fails closed independently, Nostr never elevates, and Operator is impossible", () => {
  for (const authorityResult of [{ status: "rejected", reason: new Error("secret") }, { status: "fulfilled", value: authority("operator") }, { status: "fulfilled", value: authority("full", { subject: "b".repeat(64) }) }]) {
    const snapshot = createParticipantShellSnapshot(result({ authority: authorityResult, profile: { status: "fulfilled", value: { id: subject, displayName: "Full Operator" } }, notes: { status: "fulfilled", value: [{ id: "n2", authorId: subject, audience: "PUBLIC", body: "operator claim", timestamp: "now", reactions: 0, comments: 0, reposts: 0, replies: [] }] } }));
    assert.equal(snapshot.statuses[subject], "limited");
    assert.equal(snapshot.externalAssertions[subject].valid, false);
    assert.equal(snapshot.notes.length, 0);
    assert.match(snapshot.participants[0].displayName, /^Public key/);
    assert.doesNotMatch(JSON.stringify(snapshot), /operator/i);
  }
  const limited = createParticipantShellSnapshot(result({ authority: { status: "fulfilled", value: authority("limited") } }));
  assert.equal(limited.statuses[subject], "limited");
});

test("missing profile is neutral and malformed or off-subject public data cannot enter", () => {
  const snapshot = createParticipantShellSnapshot(result({ profile: { status: "fulfilled", value: null }, notes: { status: "fulfilled", value: [{ id: "bad", authorId: "b".repeat(64), body: "off subject" }, null] } }));
  assert.match(snapshot.participants[0].displayName, /^Public key a{8}…a{6}$/);
  assert.equal(snapshot.profileAvailable, false);
  assert.deepEqual(snapshot.notes, []);
  assert.throws(() => createParticipantShellSnapshot(result({ subject: subject.toUpperCase() })), /canonical/);
  for (const noteLimit of [0, 11, 1.5, undefined]) assert.throws(() => createParticipantShellSnapshot(result({ noteLimit })), /bounded/);
});

test("only normalized PUBLIC notes enter the live snapshot", () => {
  const note = (audience) => ({ id: audience, authorId: subject, audience, body: audience, timestamp: "now", reactions: 0, comments: 0, reposts: 0, replies: [] });
  const snapshot = createParticipantShellSnapshot(result({ noteLimit: 3, notes: { status: "fulfilled", value: [note("PUBLIC"), note("FRIENDS"), note("FULL_NETWORK")] } }));
  assert.deepEqual(snapshot.notes.map(({ audience }) => audience), ["PUBLIC"]);
});
