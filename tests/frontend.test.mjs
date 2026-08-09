import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus, EdgeType, relationship } from "../src/domain.mjs";
import { edges, keys, notes, participants, statuses } from "../src/fixtures.mjs";
import { renderConnections, renderDiscovery, renderShell, selectViewer, shortKey } from "../web/app.mjs";

const data = Object.freeze({ participants, statuses, edges, notes });
const viewer = participants.find((person) => person.id === keys.ada);
const directFriend = participants.find((person) => person.id === keys.ben);
const friendOfFriend = participants.find((person) => person.id === keys.cy);

test("Limited friend-of-friend discovery renders no participant identity", () => {
  const html = renderDiscovery({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  assert.match(html, /Restricted connection/);
  assert.match(html, /Friend-of-friend discovery is unavailable/);
  for (const identity of [friendOfFriend.displayName, friendOfFriend.publicKey, shortKey(friendOfFriend.publicKey)]) assert.equal(html.includes(identity), false);
  assert.doesNotMatch(html, /class="avatar"/);
});

test("Limited discovery renders one placeholder for multiple hidden candidates", () => {
  const multipleCandidateEdges = [...edges, relationship(EdgeType.FRIEND, keys.ben, keys.dia)];
  const html = renderDiscovery({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges: multipleCandidateEdges });
  assert.equal((html.match(/Restricted connection/g) ?? []).length, 1);
  for (const hidden of [friendOfFriend, participants.find((person) => person.id === keys.dia)]) {
    for (const identity of [hidden.displayName, hidden.publicKey, shortKey(hidden.publicKey)]) assert.equal(html.includes(identity), false);
  }
  assert.doesNotMatch(html, /class="avatar"/);
});

test("Full and Operator discovery render the same permitted participant", () => {
  const full = renderDiscovery({ viewer, viewerStatus: AccessStatus.FULL, participants, edges });
  const operator = renderDiscovery({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges });
  for (const html of [full, operator]) {
    assert.match(html, new RegExp(friendOfFriend.displayName));
    assert.match(html, new RegExp(shortKey(friendOfFriend.publicKey)));
    assert.doesNotMatch(html, /Restricted connection/);
  }
  assert.equal(operator, full);
});

test("Limited viewers retain visible direct connections", () => {
  const html = renderConnections({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  assert.match(html, new RegExp(directFriend.displayName));
  assert.match(html, new RegExp(shortKey(directFriend.publicKey)));
  assert.doesNotMatch(html, /Restricted connection/);
});

test("empty discovery does not fall back to an unrelated identity", () => {
  const ben = participants.find((person) => person.id === keys.ben);
  const unrelated = participants.find((person) => person.id === keys.dia);
  const html = renderDiscovery({ viewer: ben, viewerStatus: AccessStatus.FULL, participants, edges });
  assert.match(html, /No discoverable connections/);
  for (const identity of [unrelated.displayName, unrelated.publicKey, shortKey(unrelated.publicKey)]) assert.equal(html.includes(identity), false);
});

test("switching fixture viewer changes every rendered product section", () => {
  const operator = renderShell(keys.ada, data);
  const full = renderShell(keys.ben, data);
  const limited = renderShell(keys.cy, data);
  assert.equal(selectViewer(keys.ada, keys.ben, data), keys.ben);
  assert.equal(operator.viewerStatus, AccessStatus.OPERATOR);
  assert.equal(full.viewerStatus, AccessStatus.FULL);
  assert.equal(limited.viewerStatus, AccessStatus.LIMITED);
  for (const section of ["profile", "feed", "connections", "discovery", "trust"]) assert.notEqual(operator[section], full[section]);
  assert.match(operator.profile, /Ada · synthetic/);
  assert.match(full.profile, /Ben · synthetic/);
  assert.match(limited.profile, /Cy · synthetic/);
});

test("viewer selection rejects identities outside the synthetic fixtures", () => {
  const snapshot = structuredClone(statuses);
  assert.equal(selectViewer(keys.ben, "not-a-fixture-key", data), keys.ben);
  assert.deepEqual(statuses, snapshot);
  assert.equal(Object.isFrozen(statuses), true);
});

test("unknown or missing status fails closed without participant identity", () => {
  const malformedData = { ...data, statuses: { ...statuses, [keys.ada]: "unknown" } };
  const shell = renderShell(keys.ada, malformedData);
  assert.equal(shell.viewerStatus, undefined);
  assert.match(shell.profile, /Viewer unavailable/);
  assert.doesNotMatch(shell.profile, /Ada|aaaaaaaa|operator/i);
  for (const html of [shell.feed, shell.discovery, shell.trust]) {
    for (const person of participants) {
      assert.equal(html.includes(person.displayName), false);
      assert.equal(html.includes(person.publicKey), false);
      assert.equal(html.includes(shortKey(person.publicKey)), false);
    }
    assert.doesNotMatch(html, /class="avatar"/);
  }
});

test("denied feed and discovery markup leaks no denied identity or note identifier", () => {
  const limited = renderShell(keys.ada, { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.LIMITED } });
  const deniedAuthor = participants.find((person) => person.id === keys.cy);
  for (const identity of [deniedAuthor.displayName, deniedAuthor.publicKey, shortKey(deniedAuthor.publicKey), notes[1].id]) {
    assert.equal(limited.feed.includes(identity), false);
  }
  const limitedAda = renderDiscovery({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  for (const identity of [friendOfFriend.displayName, friendOfFriend.publicKey, shortKey(friendOfFriend.publicKey)]) assert.equal(limitedAda.includes(identity), false);
});

test("friendship and sponsor-trust remain separate frontend surfaces", () => {
  const shell = renderShell(keys.ada, data);
  assert.match(shell.connections, /Direct friend · social relationship/);
  assert.doesNotMatch(shell.connections, /Sponsor-trust/);
  assert.match(shell.trust, /Trust record restricted/);
  assert.doesNotMatch(shell.trust, /Direct friend/);
});

test("frontend exposes interactive surfaces and required non-claims", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const phrase of ["Synthetic participant", "Home feed", "Participant profile", "Direct connections", "Friends of friends", "Sponsor-trust", "Limited participants", "Friendship does not prove covenant trust", "not legal identity", "does not hold funds or control private keys", "does not promise profit or investment return"]) assert.match(html, new RegExp(phrase, "i"));
  assert.doesNotMatch(html, /password|localStorage|cookie/i);
});

test("package remains dependency-free", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
});

test("frontend is responsive and presents all access modes", async () => {
  const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");
  assert.match(css, /@media/);
  assert.match(css, /grid-template-columns/);
  for (const status of Object.values(AccessStatus)) assert.match(css, new RegExp(`data-access=\\"${status}\\"`));
});
