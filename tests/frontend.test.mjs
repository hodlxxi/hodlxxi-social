import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { edges, keys, participants } from "../src/fixtures.mjs";
import { renderConnections, renderDiscovery } from "../web/app.mjs";

const viewer = participants.find((person) => person.id === keys.ada);
const directFriend = participants.find((person) => person.id === keys.ben);
const friendOfFriend = participants.find((person) => person.id === keys.cy);
const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;

test("Limited friend-of-friend discovery renders no participant identity", () => {
  const html = renderDiscovery({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  assert.equal(html, '<article class="person restricted"><div><strong>Restricted connection</strong><p class="meta">Friend-of-friend discovery is unavailable for Limited access.</p></div></article>');
  assert.match(html, /Restricted connection/);
  assert.match(html, /Friend-of-friend discovery is unavailable for Limited access/);
  assert.equal(html.includes(friendOfFriend.displayName), false);
  assert.equal(html.includes(friendOfFriend.publicKey), false);
  assert.equal(html.includes(shortKey(friendOfFriend.publicKey)), false);
  assert.doesNotMatch(html, /class="avatar"/);
});

test("Full friend-of-friend discovery renders the permitted participant", () => {
  const html = renderDiscovery({ viewer, viewerStatus: AccessStatus.FULL, participants, edges });
  assert.match(html, new RegExp(friendOfFriend.displayName));
  assert.match(html, new RegExp(shortKey(friendOfFriend.publicKey)));
  assert.doesNotMatch(html, /Restricted connection/);
});

test("Limited viewers retain visible direct connections", () => {
  const html = renderConnections({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  assert.match(html, new RegExp(directFriend.displayName));
  assert.match(html, new RegExp(shortKey(directFriend.publicKey)));
  assert.doesNotMatch(html, /Restricted connection/);
});

test("empty discovery does not fall back to an unrelated identity", () => {
  const viewerWithoutFriendOfFriend = participants.find((person) => person.id === keys.ben);
  const unrelated = participants.find((person) => person.id === keys.dia);
  const html = renderDiscovery({ viewer: viewerWithoutFriendOfFriend, viewerStatus: AccessStatus.FULL, participants, edges });
  assert.match(html, /No discoverable connections/);
  assert.equal(html.includes(unrelated.displayName), false);
  assert.equal(html.includes(unrelated.publicKey), false);
  assert.equal(html.includes(shortKey(unrelated.publicKey)), false);
});

test("frontend exposes required product surfaces and non-claims", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const phrase of ["Home feed","Participant profile","Direct connections","Friends of friends","Limited participants","Friendship does not prove covenant trust","not legal identity","does not hold funds or control private keys","does not promise profit or investment return"]) assert.match(html, new RegExp(phrase, "i"));
});
test("package remains dependency-free", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(pkg.dependencies, {}); assert.deepEqual(pkg.devDependencies, {});
});
test("frontend is responsive", async () => {
  const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");
  assert.match(css, /@media/); assert.match(css, /grid-template-columns/);
});
