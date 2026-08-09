import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus, EdgeType } from "../src/domain.mjs";
import { assertions, conversations, edges, groups, keys, notes, notifications, participants } from "../src/fixtures.mjs";
import { UnsupportedCapabilityError, declareCapabilities } from "../src/data/adapter.mjs";
import { SocialCapability } from "../src/data/capabilities.mjs";
import { HodlxxiAuthorityReadAdapter } from "../src/data/hodlxxi-authority-read-adapter.mjs";
import { createSocialDataService } from "../src/data/service.mjs";
import { SyntheticSocialAdapter } from "../src/data/synthetic-adapter.mjs";
import { relationshipContext, RelationshipContext } from "../src/visibility.mjs";
import { parseRoute, renderPage } from "../web/app.mjs";

const readCapabilities = Object.freeze([
  SocialCapability.READ_CURRENT_VIEWER, SocialCapability.READ_PARTICIPANTS, SocialCapability.READ_RELATIONSHIPS,
  SocialCapability.READ_FEED, SocialCapability.READ_GROUPS, SocialCapability.READ_MESSAGES,
  SocialCapability.READ_NOTIFICATIONS
]);

function fake(overrides = {}) {
  return {
    capabilities: declareCapabilities(overrides.capabilities ?? readCapabilities),
    getCurrentViewer: () => overrides.viewerId ?? keys.ada,
    listParticipants: () => overrides.participants ?? participants,
    listRelationships: () => overrides.edges ?? edges,
    listFeed: () => overrides.notes ?? notes,
    listGroups: () => overrides.groups ?? groups,
    listConversations: () => overrides.conversations ?? conversations,
    listNotifications: () => overrides.notifications ?? notifications
  };
}

const authority = (overrides = {}) => new HodlxxiAuthorityReadAdapter({
  readAssertion: (subject) => typeof overrides.assertion === "function" ? overrides.assertion(subject) : assertions[subject]
});

const load = (overrides = {}, options = {}) => createSocialDataService(fake(overrides), { ...options, authorityAdapter: authority(overrides) }).load();

test("synthetic adapter supplies the complete normalized product snapshot", () => {
  const adapter = new SyntheticSocialAdapter(keys.ben);
  const data = createSocialDataService(adapter, { authorityAdapter: authority() }).load();
  assert.equal(data.currentViewerId, keys.ben);
  assert.deepEqual(data.participants, participants);
  assert.deepEqual(data.notes, notes);
  assert.deepEqual(data.groups, groups);
  assert.deepEqual(data.conversations, conversations);
  assert.deepEqual(data.notifications, notifications);
  assert.equal(data.statuses[keys.ada], AccessStatus.OPERATOR);
  assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
  assert.deepEqual(data.externalAssertions[keys.cy], { subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "unavailable", valid: false });
  for (const value of [data, data.participants, data.edges, data.groups, data.conversations, data.notifications]) assert.equal(Object.isFrozen(value), true);
});

test("valid current external assertions preserve provenance independently of access level", () => {
  for (const status of [AccessStatus.LIMITED, AccessStatus.FULL, AccessStatus.OPERATOR]) {
    const evidenceRef = `crt-evidence:${status}`;
    const assertion = { source: "hodlxxi-crt", version: 1, subject: keys.cy.toUpperCase(), status, expiresAt: 200, evidenceRef };
    const adapter = fake({ assertion: (subject) => subject === keys.cy ? assertion : assertions[subject] });
    adapter.statuses = { [keys.cy]: AccessStatus.OPERATOR };
    adapter.localState = { [keys.cy]: AccessStatus.OPERATOR };
    const data = createSocialDataService(adapter, { now: 100, authorityAdapter: authority({ assertion: (subject) => subject === keys.cy ? assertion : assertions[subject] }) }).load();
    assert.deepEqual(data.externalAssertions[keys.cy], { subject: keys.cy, assertedStatus: status, source: "hodlxxi-crt", valid: true, evidenceRef });
    assert.equal(data.statuses[keys.cy], status);
  }
});

test("invalid external assertions fail closed without retaining unavailable evidence", () => {
  const elevated = { source: "hodlxxi-crt", version: 1, subject: keys.cy, status: AccessStatus.OPERATOR, expiresAt: 200, evidenceRef: "crt-evidence:operator" };
  const cases = [
    ["malformed", { ...elevated, grant: "operator" }],
    ["expired", { ...elevated, expiresAt: 100 }],
    ["unknown status", { ...elevated, status: "administrator" }],
    ["malformed evidence", { ...elevated, evidenceRef: "   " }],
    ["missing", undefined]
  ];
  for (const [label, assertion] of cases) {
    const data = load({ assertion: (subject) => subject === keys.cy ? assertion : assertions[subject] }, { now: 100 });
    assert.deepEqual(data.externalAssertions[keys.cy], { subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "unavailable", valid: false }, label);
    assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED, label);
  }
});

test("friendship, sponsor trust, and local adapter state cannot elevate a Limited assertion", () => {
  const assertion = { source: "hodlxxi-crt", version: 1, subject: keys.cy, status: AccessStatus.LIMITED, expiresAt: 200, evidenceRef: "crt-evidence:limited" };
  const adapter = fake({
    edges: [...edges, { type: EdgeType.FRIEND, from: keys.ada, to: keys.cy }, { type: EdgeType.SPONSOR_TRUST, from: keys.ada, to: keys.cy }],
    assertion: (subject) => subject === keys.cy ? assertion : assertions[subject]
  });
  adapter.statuses = { [keys.cy]: AccessStatus.OPERATOR };
  adapter.localState = { [keys.cy]: AccessStatus.OPERATOR };
  const data = createSocialDataService(adapter, { authorityAdapter: authority({ assertion: (subject) => subject === keys.cy ? assertion : assertions[subject] }) }).load();
  assert.equal(data.externalAssertions[keys.cy].valid, true);
  assert.equal(data.externalAssertions[keys.cy].assertedStatus, AccessStatus.LIMITED);
  assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
});

test("capabilities are declared explicitly and missing capability fails safely", () => {
  const capabilities = readCapabilities.filter((value) => value !== SocialCapability.READ_FEED);
  assert.throws(() => createSocialDataService(fake({ capabilities })).load(), UnsupportedCapabilityError);
  const withoutViewer = readCapabilities.filter((value) => value !== SocialCapability.READ_CURRENT_VIEWER);
  assert.throws(() => createSocialDataService(fake({ capabilities: withoutViewer })).load(), UnsupportedCapabilityError);
  assert.throws(() => declareCapabilities(["arbitrary-query"]), TypeError);
});

test("malformed participant and relationship adapter results are rejected", () => {
  assert.throws(() => createSocialDataService(fake({ participants: [{ id: keys.ada, publicKey: keys.ben, displayName: "mismatch" }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ participants: [{ id: keys.ada, publicKey: keys.ada, displayName: "Ada", privateKey: "not accepted" }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ edges: [{ type: "covenant-implies-friend", from: keys.ada, to: keys.dia }] })).load(), TypeError);
  const unknown = "f".repeat(64);
  assert.throws(() => createSocialDataService(fake({ edges: [{ type: EdgeType.FRIEND, from: keys.ada, to: unknown }, { type: EdgeType.FRIEND, from: unknown, to: keys.dia }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ notifications: [{ ...notifications[0], unread: "false" }] })).load(), TypeError);
});

test("collection identities and record ids require canonical referential integrity", () => {
  const unknown = "f".repeat(64);
  assert.throws(() => createSocialDataService(fake({ notes: [{ ...notes[0], authorId: unknown }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ groups: [{ ...groups[0], memberIds: [...groups[0].memberIds, unknown] }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ conversations: [{ ...conversations[0], messages: [{ ...conversations[0].messages[0], authorId: keys.cy }] }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ notifications: [{ ...notifications[0], actorId: unknown }] })).load(), TypeError);
  assert.throws(() => createSocialDataService(fake({ groups: [groups[0], { ...groups[1], id: groups[0].id }] })).load(), TypeError);
});

test("normalized adapter display names are escaped before rendering", () => {
  const malicious = participants.map((person) => person.id === keys.ada ? { ...person, displayName: '<img src=x onerror="alert(1)">' } : person);
  const data = load({ participants: malicious });
  const html = renderPage(parseRoute("#/profile/" + keys.ada), keys.ada, data);
  assert.doesNotMatch(html, /<img/i);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
});

test("unknown viewer and malformed elevated assertions fail closed", () => {
  const malformed = load({ viewerId: "f".repeat(64), assertion: (subject) => subject === keys.cy ? { source: "hodlxxi-crt", version: 1, subject: keys.ada, status: AccessStatus.OPERATOR, expiresAt: 200 } : assertions[subject] });
  assert.equal(malformed.currentViewerId, undefined);
  assert.equal(malformed.statuses[keys.cy], AccessStatus.LIMITED);
  const unknown = load({ assertion: () => undefined });
  assert.deepEqual(new Set(Object.values(unknown.statuses)), new Set([AccessStatus.LIMITED]));
});

test("friend and sponsor-trust normalization remain separate", () => {
  const data = load();
  assert.deepEqual(data.friendEdges.map(({ type }) => type), [EdgeType.FRIEND, EdgeType.FRIEND]);
  assert.deepEqual(data.sponsorTrustEdges.map(({ type }) => type), [EdgeType.SPONSOR_TRUST]);
  assert.equal(relationshipContext(keys.ada, keys.dia, data.edges), RelationshipContext.UNRELATED);
});

test("active boundary contains no network, secret, signing, or authority mutation path", async () => {
  const sources = await Promise.all(["adapter.mjs", "capabilities.mjs", "hodlxxi-authority-read-adapter.mjs", "normalize.mjs", "service.mjs", "synthetic-adapter.mjs"].map((name) => readFile(new URL(`../src/data/${name}`, import.meta.url), "utf8")));
  for (const source of sources) assert.doesNotMatch(source, /WebSocket|fetch\(|XMLHttpRequest|process\.env|localStorage|sessionStorage|indexedDB|private.?key|\.publish\(|grantFull|setOperator|approveTrust|issueCRT|bitcoin|lightning|custody/i);
});
