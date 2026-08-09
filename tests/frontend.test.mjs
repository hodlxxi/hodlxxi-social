import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus, EdgeType, relationship } from "../src/domain.mjs";
import { edges, keys, notes, participants, statuses } from "../src/fixtures.mjs";
import { parseRoute, profileAccess, profileRoute, renderConnections, renderDiscovery, renderNavigation, renderPage, renderShell, routeFor, selectViewer, shortKey } from "../web/app.mjs";
import { Audience, audienceDecision, prependLocalPost, renderComposer, renderContextSummary, renderFeed as renderSocialFeed, toggleReaction, visibleFeed } from "../web/feed.mjs";

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
  assert.match(shell.profile, /Profile restricted/);
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
  const app = await readFile(new URL("../web/app.mjs", import.meta.url), "utf8");
  for (const phrase of ["Synthetic participant", "Friendship does not prove covenant trust", "not legal identity", "does not hold funds or control private keys", "does not promise profit or investment return"]) assert.match(html, new RegExp(phrase, "i"));
  for (const phrase of ["Home", "My Circle", "Participant Profile", "Direct friends", "Friends of Friends", "Sponsor-trust"]) assert.match(app, new RegExp(phrase, "i"));
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

test("hash routes select every required local surface", () => {
  const cases = [["#/home", "home"], ["#/circle", "circle"], ["#/friends", "friends"], ["#/friends-of-friends", "discovery"], [profileRoute(keys.ben), "profile"], ["#/trust", "trust"]];
  for (const [hash, page] of cases) {
    const route = parseRoute(hash);
    assert.equal(route.page, page);
    assert.match(renderPage(route, keys.ben, data), new RegExp(page === "discovery" ? "Friends of Friends" : page, "i"));
  }
  assert.equal(routeFor("home", keys.ben), "#/home");
  assert.equal(routeFor("profile", keys.ben), profileRoute(keys.ben));
});

test("unknown and malformed routes fail safely", () => {
  for (const hash of ["#/unknown", "#/profile/not-a-key", "#/profile/" ]) {
    const route = parseRoute(hash);
    assert.equal(route.page, "not-found");
    const html = renderPage(route, keys.ada, data);
    assert.match(html, /Page unavailable|Route not found/);
    for (const person of participants) assert.equal(html.includes(person.publicKey), false);
  }
});

test("direct friend profile route renders permitted identity and relationship", () => {
  const html = renderPage(parseRoute(profileRoute(keys.ada)), keys.ben, data);
  assert.match(html, /Ada · synthetic/);
  assert.match(html, new RegExp(shortKey(keys.ada)));
  assert.match(html, /direct social friend/i);
  assert.match(html, /Sponsor-trust/);
  assert.match(html, /not legal identity/);
});

test("Full viewer can open a permitted friend-of-friend profile", () => {
  const html = renderPage(parseRoute(profileRoute(keys.cy)), keys.ada, data);
  assert.match(html, /Cy · synthetic/);
  assert.match(html, /friend-of-friend/);
  assert.match(html, /limited/);
});

test("Limited viewer direct profile URL cannot reveal denied friend-of-friend", () => {
  const limitedData = { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.LIMITED } };
  const html = renderPage(parseRoute(profileRoute(keys.cy)), keys.ada, limitedData);
  assert.match(html, /Profile restricted/);
  const denied = participants.find((person) => person.id === keys.cy);
  for (const identity of [denied.displayName, denied.publicKey, shortKey(denied.publicKey), denied.displayName[0], "friend-of-friend"]) assert.equal(html.includes(identity), false);
  assert.doesNotMatch(html, /class="avatar|badge-/);
});

test("unknown profile subject fails closed without stable identity", () => {
  const unknown = "e".repeat(64);
  const route = parseRoute(profileRoute(unknown));
  const html = renderPage(route, keys.ada, data);
  assert.match(html, /Profile restricted/);
  assert.equal(html.includes(unknown), false);
  assert.doesNotMatch(html, /class="avatar|badge-/);
});

test("profile access consumes canonical graph visibility", () => {
  const full = profileAccess({ viewer, viewerStatus: AccessStatus.FULL, subjectId: keys.cy, participants, edges });
  const limited = profileAccess({ viewer, viewerStatus: AccessStatus.LIMITED, subjectId: keys.cy, participants, edges });
  assert.equal(full.visible, true);
  assert.equal(full.context, "friend-of-friend");
  assert.deepEqual(limited, { visible: false, reason: "restricted" });
});

test("viewer switching recomputes the active routed profile", () => {
  const route = parseRoute(profileRoute(keys.cy));
  const full = renderShell(keys.ada, data, route);
  const direct = renderShell(keys.ben, data, route);
  const self = renderShell(keys.cy, data, route);
  assert.match(full.page, /friend-of-friend/);
  assert.match(direct.page, /direct social friend/i);
  assert.match(self.page, /<dd>self<\/dd>/);
  assert.notEqual(full.navigation, direct.navigation);
});

test("navigation renders active state and all required destinations", () => {
  const html = renderNavigation(parseRoute("#/circle"), keys.ben);
  for (const label of ["Home", "My Circle", "Friends", "Friends of Friends", "Profile", "Trust"]) assert.match(html, new RegExp(label));
  assert.match(html, /href="#\/circle" aria-current="page"/);
});

test("frontend cannot grant an externally-derived elevated status", () => {
  const snapshot = structuredClone(statuses);
  for (const requested of ["full", "operator", "not-a-fixture-key"]) selectViewer(keys.cy, requested, data);
  assert.deepEqual(statuses, snapshot);
  assert.equal(renderShell(keys.cy, data).viewerStatus, AccessStatus.LIMITED);
});

test("Home renders the local composer before a rich synthetic feed", () => {
  const html = renderPage(parseRoute("#/home"), keys.ada, data);
  assert.ok(html.indexOf('id="local-composer"') < html.indexOf('class="feed-stack"'));
  for (const phrase of ["Post locally", "PUBLIC", "FULL NETWORK", "FRIENDS", "Comments", "Reposts", "Bookmark locally", "synthetic fixture", "Visible local replies"]) assert.match(html, new RegExp(phrase, "i"));
  assert.match(html, /badge-(full|operator)/);
  assert.match(html, /Local network map/);
});

test("composer fails closed for an unknown viewer or status", () => {
  const unknownViewer = renderComposer({ viewer: undefined, viewerStatus: AccessStatus.FULL, ...data });
  const unknownStatus = renderComposer({ viewer, viewerStatus: "unknown", ...data });
  const wellFormedUnknown = renderComposer({ viewer: { id: "e".repeat(64), displayName: "Hidden" }, viewerStatus: AccessStatus.FULL, ...data });
  const malformedUnknown = renderComposer({ viewer: { id: "malformed", displayName: "Hidden" }, viewerStatus: AccessStatus.FULL, ...data });
  for (const html of [unknownViewer, unknownStatus, wellFormedUnknown, malformedUnknown]) {
    assert.match(html, /Composer unavailable/);
    assert.doesNotMatch(html, /textarea|Post locally|Ada|aaaaaaaa/i);
  }
});

test("local post insertion is immutable and preserves viewer identity without status fields", () => {
  const before = [...notes];
  const inserted = prependLocalPost(before, { viewer, viewerStatus: AccessStatus.OPERATOR, participants, statuses, audience: Audience.FRIENDS, body: "  Local only  " });
  assert.equal(inserted.length, before.length + 1);
  assert.equal(inserted[0].authorId, viewer.id);
  assert.equal(inserted[0].body, "Local only");
  assert.equal(inserted[0].local, true);
  assert.equal("viewerStatus" in inserted[0], false);
  assert.deepEqual(before, [...notes]);
  assert.equal(Object.isFrozen(inserted), true);
  assert.equal(prependLocalPost(before, { viewer, viewerStatus: AccessStatus.OPERATOR, participants, statuses, audience: "UNKNOWN", body: "denied" }).length, before.length);
  for (const id of ["e".repeat(64), "malformed"]) assert.equal(prependLocalPost(before, { viewer: { id, displayName: "Hidden" }, viewerStatus: AccessStatus.FULL, participants, statuses, audience: Audience.PUBLIC, body: "denied" }).length, before.length);
});

test("audience decisions are deterministic and unknown values fail closed", () => {
  assert.equal(audienceDecision({ audience: Audience.PUBLIC, viewerStatus: AccessStatus.LIMITED, context: "direct" }).visible, true);
  assert.equal(audienceDecision({ audience: Audience.FULL_NETWORK, viewerStatus: AccessStatus.LIMITED, context: "direct" }).visible, false);
  assert.equal(audienceDecision({ audience: Audience.FRIENDS, viewerStatus: AccessStatus.FULL, context: "friend-of-friend" }).visible, false);
  assert.equal(audienceDecision({ audience: "UNKNOWN", viewerStatus: AccessStatus.FULL, context: "direct" }).visible, false);
});

test("feed audiences and canonical identity visibility compose without leaks", () => {
  const limitedData = { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.LIMITED } };
  const limitedCommon = { viewer, viewerStatus: AccessStatus.LIMITED, ...limitedData };
  const fullCommon = { viewer, viewerStatus: AccessStatus.FULL, ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.FULL } };
  const limitedHtml = renderSocialFeed(limitedCommon);
  const fullHtml = renderSocialFeed(fullCommon);
  assert.match(limitedHtml, /Ben · synthetic/);
  for (const hidden of [friendOfFriend.displayName, friendOfFriend.publicKey, notes[1].id, "synthetic-reply-2"]) assert.equal(limitedHtml.includes(hidden), false);
  assert.match(fullHtml, /Ben · synthetic/);
  assert.match(fullHtml, /Ada · synthetic/);
  assert.match(fullHtml, /Cy · synthetic/);
  assert.equal(visibleFeed(fullCommon).some((note) => note.authorId === keys.cy), false);
  assert.equal(visibleFeed({ ...fullCommon, viewer: undefined }).length, 0);
  for (const id of ["e".repeat(64), "malformed"]) assert.doesNotThrow(() => assert.equal(visibleFeed({ ...fullCommon, viewer: { id, displayName: "Hidden" } }).length, 0));
});

test("feed excludes authors whose external status is missing or invalid", () => {
  for (const value of [undefined, "unknown"]) {
    const alteredStatuses = { ...statuses, [keys.ben]: value };
    const html = renderSocialFeed({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, statuses: alteredStatuses, edges, notes });
    assert.equal(html.includes(directFriend.displayName), false);
    assert.equal(html.includes(notes[0].id), false);
    assert.doesNotMatch(html, /badge-unknown/);
  }
});

test("visible feed authors link only to permitted canonical profile routes", () => {
  const fullData = { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.FULL } };
  const html = renderSocialFeed({ viewer, viewerStatus: AccessStatus.FULL, ...fullData });
  assert.match(html, new RegExp(profileRoute(keys.ben).replaceAll("/", "\\/")));
  assert.match(html, new RegExp(profileRoute(keys.ada).replaceAll("/", "\\/")));
  assert.match(html, new RegExp(profileRoute(keys.cy).replaceAll("/", "\\/")));
  assert.equal(visibleFeed({ viewer, viewerStatus: AccessStatus.FULL, ...fullData }).some((note) => note.authorId === keys.cy), false);
});

test("reaction state is immutable local UI state", () => {
  const state = Object.freeze({});
  const active = toggleReaction(state, notes[0].id);
  const inactive = toggleReaction(active, notes[0].id);
  assert.deepEqual(state, {});
  assert.equal(active[notes[0].id], true);
  assert.equal(inactive[notes[0].id], false);
});

test("context rail labels all activity as external or synthetic rather than live", () => {
  const html = renderContextSummary({ viewer, viewerStatus: AccessStatus.OPERATOR, ...data });
  assert.match(html, /externally derived/i);
  assert.match(html, /Synthetic fixture posts/);
  assert.match(html, /Not live network activity or a trust score/);
  assert.doesNotMatch(html, /active users|live users/i);
});
