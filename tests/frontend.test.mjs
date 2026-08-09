import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus, EdgeType, relationship } from "../src/domain.mjs";
import { edges, keys, notes, participants, statuses } from "../src/fixtures.mjs";
import { parseRoute, profileAccess, profileRoute, renderConnections, renderDiscovery, renderNavigation, renderPage, renderShell, routeFor, selectViewer, shortKey } from "../web/app.mjs";
import { Audience, audienceDecision, prependLocalPost, renderComposer, renderContextSummary, renderFeed as renderSocialFeed, toggleReaction, visibleFeed } from "../web/feed.mjs";
import { deriveCircleGraph, renderCircle, ringLayout } from "../web/circle.mjs";
import { appendLocalMessage, conversationAccess, conversations, initializeLocalMessages, renderMessages, visibleConversations } from "../web/messages.mjs";
import { groupAccess, groups, renderGroups } from "../web/groups.mjs";
import { deriveNotifications, initializeNotificationState, markAllNotificationsRead, markNotificationRead, notifications, renderNotifications, safeNotificationRoute, unreadCount, visibleUnreadCount } from "../web/notifications.mjs";
import { deriveActivity, renderActivity } from "../web/activity.mjs";

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

test("circle graph places the viewer at center and social relationships on deterministic rings", () => {
  const graph = deriveCircleGraph({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges });
  assert.equal(graph.available, true);
  assert.equal(graph.nodes[0].person.id, viewer.id);
  assert.equal(graph.nodes[0].ring, "center");
  assert.equal(graph.nodes.find((node) => node.person?.id === keys.ben).ring, "inner");
  assert.equal(graph.nodes.find((node) => node.person?.id === keys.cy).ring, "outer");
  assert.deepEqual(graph, deriveCircleGraph({ viewer, viewerStatus: AccessStatus.OPERATOR, participants: [...participants].reverse(), edges }));
  assert.deepEqual(ringLayout([{ value: 1 }, { value: 2 }]), ringLayout([{ value: 1 }, { value: 2 }]));
});

test("Full and Operator circle graphs expose the same permitted friend-of-friend", () => {
  for (const viewerStatus of [AccessStatus.FULL, AccessStatus.OPERATOR]) {
    const html = renderCircle({ viewer, viewerStatus, participants, edges });
    assert.match(html, /Cy · synthetic/);
    assert.match(html, new RegExp(profileRoute(keys.cy).replaceAll("/", "\\/")));
    assert.match(html, /circle-node-outer/);
  }
});

test("Limited circle markup represents restricted reach without denied identity", () => {
  const html = renderCircle({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  for (const identity of [friendOfFriend.displayName, friendOfFriend.publicKey, shortKey(friendOfFriend.publicKey), profileRoute(friendOfFriend.id)]) assert.equal(html.includes(identity), false);
  assert.match(html, /Restricted reach/);
  assert.match(html, /<dt>Restricted reach<\/dt><dd>1<\/dd>/);
  assert.doesNotMatch(html, /circle-node-restricted[^>]*(?:href|data-)|Restricted reach[^<]*<\/text><a/);
});

test("sponsor-trust is a separate overlay and never creates circle reachability", () => {
  const graph = deriveCircleGraph({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges });
  assert.equal(graph.nodes.some((node) => node.person?.id === keys.dia), false);
  assert.equal(graph.socialEdges.every((edge) => edge.type === "friend"), true);
  assert.equal(graph.trustEdges.length, 1);
  assert.equal(graph.trustEdges[0].type, "sponsor-trust");
  assert.equal(graph.trustEdges[0].restricted, true);
  const html = renderCircle({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges });
  assert.match(html, /trust-edge/);
  assert.match(html, /Sponsor-trust · external provenance/);
  assert.doesNotMatch(html, /Dia · synthetic|dddddddd/);
});

test("permitted circle nodes navigate to profiles while restricted nodes do not", () => {
  const html = renderCircle({ viewer, viewerStatus: AccessStatus.LIMITED, participants, edges });
  assert.match(html, new RegExp(profileRoute(keys.ada).replaceAll("/", "\\/")));
  assert.match(html, new RegExp(profileRoute(keys.ben).replaceAll("/", "\\/")));
  assert.equal(html.includes(profileRoute(keys.cy)), false);
  const routed = renderPage(parseRoute(profileRoute(keys.cy)), keys.ada, { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.LIMITED } });
  assert.match(routed, /Profile restricted/);
  assert.equal(routed.includes(friendOfFriend.displayName), false);
});

test("unknown circle viewers and statuses fail closed", () => {
  for (const input of [{ viewer: undefined, viewerStatus: AccessStatus.FULL }, { viewer, viewerStatus: "unknown" }, { viewer: { id: "e".repeat(64), displayName: "Hidden" }, viewerStatus: AccessStatus.FULL }]) {
    const html = renderCircle({ ...input, participants, edges });
    assert.match(html, /Circle unavailable/);
    for (const person of participants) assert.equal(html.includes(person.displayName), false);
    assert.doesNotMatch(html, /<svg|href=/);
  }
});

test("circle route recomputes for viewer changes and has accessible local-only copy", () => {
  const route = parseRoute("#/circle");
  const ada = renderShell(keys.ada, data, route).page;
  const ben = renderShell(keys.ben, data, route).page;
  assert.notEqual(ada, ben);
  for (const phrase of ["My Circle social topology", "current participant is centered", "Synthetic fixture", "Not live network activity", "friendship does not prove covenant trust"]) assert.match(ada, new RegExp(phrase, "i"));
  assert.match(ada, /aria-labelledby="circle-title circle-description"/);
});

test("circle styles constrain the graph on mobile without replacing bottom navigation", async () => {
  const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");
  assert.match(css, /\.circle-canvas\{[^}]*overflow:hidden/);
  assert.match(css, /@media\(max-width:720px\)[\s\S]*\.circle-product\{width:100%;max-width:100%\}/);
  assert.match(css, /\.mobile-nav\{position:fixed;bottom:0/);
});

test("Messages and Groups hash routes render local product surfaces", () => {
  for (const [hash, page, phrase] of [["#/messages", "messages", "Local demo messaging"], ["#/messages/chat-01", "messages", "Selected conversation"], ["#/groups", "groups", "Local group fixtures"], ["#/groups/group-01", "groups", "Local group detail"]]) {
    const route = parseRoute(hash);
    assert.equal(route.page, page);
    assert.match(renderPage(route, keys.ada, data), new RegExp(phrase, "i"));
  }
  for (const label of ["Messages", "Groups"]) assert.match(renderNavigation(parseRoute("#/messages"), keys.ada), new RegExp(label));
});

test("local identifiers are synthetic slugs and malformed detail routes fail closed", () => {
  for (const item of [...conversations, ...groups]) {
    assert.match(item.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    for (const person of participants) {
      assert.equal(item.id.includes(person.id), false);
      assert.equal(item.id.toLowerCase().includes(person.displayName.split(" ")[0].toLowerCase()), false);
    }
  }
  for (const hash of ["#/messages/unknown", "#/groups/unknown", "#/messages/Bad_ID", `#/groups/${keys.cy}`]) {
    const route = parseRoute(hash);
    const html = renderPage(route, keys.ada, data);
    assert.match(html, /restricted|Route not found/i);
    assert.equal(html.includes(keys.cy), false);
  }
});

test("Limited viewer cannot reveal denied conversation identity or metadata", () => {
  const limitedData = { ...data, statuses: { ...statuses, [keys.ada]: AccessStatus.LIMITED } };
  const common = { viewer, viewerStatus: AccessStatus.LIMITED, ...limitedData };
  assert.deepEqual(conversationAccess({ ...common, conversationId: "chat-02" }), { visible: false, reason: "restricted" });
  assert.equal(visibleConversations(common).some(({ conversation }) => conversation.id === "chat-02"), false);
  for (const html of [renderMessages(common), renderMessages(common, "chat-02"), renderPage(parseRoute("#/messages/chat-02"), keys.ada, limitedData)]) {
    for (const identity of [friendOfFriend.displayName, friendOfFriend.publicKey, shortKey(friendOfFriend.publicKey), "chat-02", "Visibility still follows"]) assert.equal(html.includes(identity), false);
    assert.doesNotMatch(html, /data-(?:participant|member|author)|title="[^"]*Cy|aria-label="[^"]*Cy/i);
  }
});

test("local message insertion is immutable, viewer-bound, and resettable", () => {
  const state = initializeLocalMessages();
  const snapshot = structuredClone(statuses);
  const inserted = appendLocalMessage(state, { conversationId: "chat-01", viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges, body: "  <local only>  ", timestamp: "Now · test" });
  assert.equal(inserted["chat-01"].length, state["chat-01"].length + 1);
  assert.deepEqual(inserted["chat-01"].at(-1), { authorId: viewer.id, body: "<local only>", timestamp: "Now · test", local: true });
  assert.equal("viewerStatus" in inserted["chat-01"].at(-1), false);
  assert.deepEqual(statuses, snapshot);
  assert.deepEqual(initializeLocalMessages(), state);
  assert.notEqual(initializeLocalMessages(), state);
  assert.equal(appendLocalMessage(state, { conversationId: "chat-02", viewer, viewerStatus: AccessStatus.LIMITED, participants, edges, body: "denied" }), state);
  assert.match(renderMessages({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges }, "chat-01", inserted), /&lt;local only&gt;/);
  assert.doesNotThrow(() => structuredClone(state));
});

test("group detail filters denied members and inaccessible groups fail closed", () => {
  const limitedCommon = { viewer, viewerStatus: AccessStatus.LIMITED, participants, edges };
  const access = groupAccess({ ...limitedCommon, groupId: "group-01" });
  assert.equal(access.visible, true);
  assert.equal(access.members.filter((member) => !member.visible).length, 1);
  const html = renderGroups(limitedCommon, "group-01");
  assert.match(html, /Restricted participant/);
  for (const identity of [friendOfFriend.displayName, friendOfFriend.publicKey, shortKey(friendOfFriend.publicKey)]) assert.equal(html.includes(identity), false);
  const denied = renderGroups(limitedCommon, "group-02");
  assert.match(denied, /Group restricted/);
  assert.doesNotMatch(denied, /Design Study|Dia · synthetic|dddddddd/);
});

test("messaging and groups make honest local non-claims without integration paths", async () => {
  const messagesSource = await readFile(new URL("../web/messages.mjs", import.meta.url), "utf8");
  const groupsSource = await readFile(new URL("../web/groups.mjs", import.meta.url), "utf8");
  const html = renderMessages({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges }, "chat-01");
  for (const phrase of ["Local demo", "not transported", "not encrypted", "Nothing is delivered or persisted", "not trust", "does not grant authentication or protocol authority"]) assert.match(html, new RegExp(phrase, "i"));
  assert.match(renderGroups({ viewer, viewerStatus: AccessStatus.OPERATOR, participants, edges }, "group-01"), /no Nostr interoperability or group authority/i);
  for (const source of [messagesSource, groupsSource]) {
    assert.doesNotMatch(source, /from ["'][^"']*nostr|createNostrBoundary|\.publish\(|\.read\(|localStorage|sessionStorage|indexedDB|WebSocket|fetch\(|type=["']password|private.?key/i);
  }
});

test("Messages and Groups responsive styles preserve mobile bottom navigation", async () => {
  const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");
  for (const selector of [".split-surface", ".conversation-row.selected", ".conversation-row.unread", ".message-transcript", ".message-composer", ".group-members"]) assert.match(css, new RegExp(selector.replace(".", "\\.")));
  assert.match(css, /@media\(max-width:720px\)[\s\S]*\.surface-list\{display:flex/);
  assert.match(css, /\.mobile-nav\{position:fixed;bottom:0/);
});

test("Notifications and Activity routes render and navigation carries unread state", () => {
  const state = initializeNotificationState();
  assert.equal(parseRoute("#/notifications").page, "notifications");
  assert.equal(parseRoute("#/activity").page, "activity");
  assert.match(renderPage(parseRoute("#/notifications"), keys.ada, data, { notificationState: state }), /Local demo notifications/);
  assert.match(renderPage(parseRoute("#/activity"), keys.ada, data, { reactions: {} }), /Local synthetic activity/);
  const desktop = renderNavigation(parseRoute("#/notifications"), keys.ada, "nav-links", unreadCount(state));
  const mobile = renderNavigation(parseRoute("#/home"), keys.ada, "mobile-nav", unreadCount(state));
  for (const html of [desktop, mobile]) {
    assert.match(html, /Notifications/);
    assert.match(html, /Activity/);
    assert.match(html, /3 unread local notifications/);
  }
});

test("notification read helpers are deterministic immutable local state", () => {
  const initial = initializeNotificationState();
  const reset = initializeNotificationState();
  assert.notEqual(initial, reset);
  assert.deepEqual(initial, reset);
  assert.equal(unreadCount(initial), 3);
  const oneRead = markNotificationRead(initial, "local-notice-friend");
  assert.equal(unreadCount(oneRead), 2);
  assert.equal(initial["local-notice-friend"], true);
  const allRead = markAllNotificationsRead(oneRead);
  assert.equal(unreadCount(allRead), 0);
  assert.equal(unreadCount(initial), 3);
  assert.deepEqual(notifications.map((item) => item.unread), [true, true, false, true, false]);
});

test("Limited notifications render denied identity generically with no route or metadata", () => {
  const limited = { ...data, viewer, viewerStatus: AccessStatus.LIMITED };
  const html = renderNotifications(limited, initializeNotificationState());
  assert.match(html, /Restricted network activity/);
  assert.equal((html.match(/Restricted network activity/g) ?? []).length, 1);
  for (const leaked of [friendOfFriend.displayName, friendOfFriend.publicKey, "local-notice-reply"]) assert.equal(html.includes(leaked), false);
  assert.doesNotMatch(html, />C<\/span>|aria-hidden="true">C</);
  assert.doesNotMatch(html, new RegExp(`profile/${keys.cy}|data-notification=.[^\"]*reply|aria-label=.[^\"]*Cy|title=.[^\"]*Cy`, "i"));
  const denied = notifications.find((item) => item.actorId === keys.cy);
  assert.equal(safeNotificationRoute(denied, limited), undefined);
  assert.deepEqual(deriveNotifications(limited).find((item) => item.restricted), { restricted: true });
  const deniedUnread = Object.freeze({ ...initializeNotificationState(), "local-notice-reply": true });
  assert.equal(unreadCount(deniedUnread), 4);
  assert.equal(visibleUnreadCount(limited, deniedUnread), 3);
  assert.match(renderNotifications(limited, deniedUnread), /3 unread locally/);
});

test("permitted profile, message, group, and Home notification targets are access-safe", () => {
  const common = { ...data, viewer, viewerStatus: AccessStatus.OPERATOR };
  const routes = Object.fromEntries(notifications.map((item) => [item.kind, safeNotificationRoute(item, common)]));
  assert.equal(routes.friend, `#/profile/${keys.ada}`);
  assert.equal(routes.reaction, "#/home");
  assert.equal(routes.message, "#/messages/chat-01");
  assert.equal(routes.group, "#/groups/group-01");
  const limitedCy = { ...data, viewer: friendOfFriend, viewerStatus: AccessStatus.LIMITED };
  const inaccessibleMessage = notifications.find((item) => item.kind === "message");
  assert.equal(safeNotificationRoute(inaccessibleMessage, limitedCy), undefined);
});

test("Activity is viewer-scoped local summary with authority non-claims", () => {
  const snapshot = structuredClone(statuses);
  const common = { ...data, statuses: { ...statuses, [viewer.id]: AccessStatus.LIMITED }, viewer, viewerStatus: AccessStatus.LIMITED };
  const derived = deriveActivity(common, { [notes[0].id]: true });
  assert.deepEqual(derived.map((item) => item.label), ["Recent posts", "Your reactions", "Direct-friend activity", "Messages", "Groups"]);
  assert.equal(derived.find((item) => item.label === "Your reactions").value, 1);
  const deniedReaction = deriveActivity(common, { [notes[1].id]: true, "missing-post": true });
  assert.equal(deniedReaction.find((item) => item.label === "Your reactions").value, 0);
  const html = renderActivity(common, { [notes[0].id]: true });
  for (const phrase of ["Local synthetic activity", "not live network telemetry", "not active-user, transaction, trust, or reputation scores", "cannot change externally derived CRT status", "grant Operator authority"]) assert.match(html, new RegExp(phrase, "i"));
  assert.deepEqual(statuses, snapshot);
});

test("notification and activity sources avoid persistence, network, and authority mutation surfaces", async () => {
  const sources = await Promise.all(["notifications.mjs", "activity.mjs"].map((name) => readFile(new URL(`../web/${name}`, import.meta.url), "utf8")));
  for (const source of sources) assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|document\.cookie|WebSocket|fetch\(|createNostrBoundary|deriveAccess|private.?key|\.publish\(/i);
  const notificationHtml = renderNotifications({ ...data, viewer, viewerStatus: AccessStatus.OPERATOR });
  for (const phrase of ["synthetic", "not live network telemetry", "do not prove covenant trust", "grant Full or Operator status", "externally derived and read-only"]) assert.match(notificationHtml, new RegExp(phrase, "i"));
});

test("Notifications and Activity styles preserve readable scroll-safe mobile navigation", async () => {
  const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");
  for (const selector of [".nav-badge", ".notification-row.unread", ".notification-toolbar", ".activity-row"]) assert.match(css, new RegExp(selector.replace(".", "\\.")));
  assert.match(css, /@media\(max-width:720px\)[\s\S]*\.mobile-nav\{justify-content:flex-start;max-width:100vw\}/);
  assert.match(css, /\.mobile-nav\{position:fixed;bottom:0[\s\S]*overflow-x:auto/);
});
