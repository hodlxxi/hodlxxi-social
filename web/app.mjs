import { EdgeType } from "../src/domain.mjs";
import { assertions } from "../src/fixtures.mjs";
import { createComposedSocialDataService } from "../src/data/composition.mjs";
import { HodlxxiAuthorityReadAdapter } from "../src/data/hodlxxi-authority-read-adapter.mjs";
import { SyntheticSocialAdapter } from "../src/data/synthetic-adapter.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { prependLocalPost, renderContextSummary, renderFeed as renderSocialFeed, renderHome, toggleReaction } from "./feed.mjs";
import { renderCircle } from "./circle.mjs";
import { appendLocalMessage, initializeLocalMessages, renderMessages } from "./messages.mjs";
import { renderGroups } from "./groups.mjs";
import { initializeNotificationState, markAllNotificationsRead, markNotificationRead, renderNotifications, visibleUnreadCount } from "./notifications.mjs";
import { renderActivity } from "./activity.mjs";
import { normalizeQuery, parseSearchQuery, renderSearch } from "./search.mjs";
import { renderLocalDiscovery } from "./discovery.mjs";
import { escapeHtml, renderEmptyState, renderPageFrame, renderRestrictedState, renderStatusBadge, renderUnavailableState } from "./components.mjs";
import { navigationModel, renderNavigation } from "./shell.mjs";

const fixtureAuthority = new HodlxxiAuthorityReadAdapter({ readAssertion: (subject) => assertions[subject] });
const fixtureData = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(), authorityAdapter: fixtureAuthority }).load();
const validStatuses = new Set(["limited", "full", "operator"]);
const pageRoutes = Object.freeze({ home: "/home", search: "/search", discover: "/discover", circle: "/circle", friends: "/friends", discovery: "/friends-of-friends", messages: "/messages", groups: "/groups", notifications: "/notifications", activity: "/activity", trust: "/trust" });
export { navigationModel, renderNavigation };

export const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;
export const profileRoute = (subjectId) => `#/profile/${subjectId}`;

export function parseRoute(hash = "") {
  const value = typeof hash === "string" ? hash : "";
  const path = value.startsWith("#") ? value.slice(1) : value;
  if (path === "/search" || path.startsWith("/search?")) {
    const parsed = parseSearchQuery(path);
    return Object.freeze({ page: "search", path: "/search", searchQuery: parsed.query, queryValid: parsed.valid });
  }
  const page = Object.entries(pageRoutes).find(([, route]) => route === path)?.[0];
  if (page) return Object.freeze({ page, path });
  const match = path.match(/^\/profile\/([0-9a-fA-F]{64})$/);
  if (match) return Object.freeze({ page: "profile", path, subjectId: match[1].toLowerCase() });
  const localMatch = path.match(/^\/(messages|groups)\/([a-z0-9]+(?:-[a-z0-9]+)*)$/);
  if (localMatch) return Object.freeze({ page: localMatch[1], path, localId: localMatch[2] });
  return Object.freeze({ page: "not-found", path: "/not-found" });
}

export function routeFor(page, viewerId) {
  if (page === "profile") return profileRoute(viewerId);
  return `#${pageRoutes[page] ?? "/not-found"}`;
}

const personCard = (person, detail) => `<a class="person person-link" href="${profileRoute(person.id)}"><div class="avatar" aria-hidden="true">${escapeHtml(person.displayName[0])}</div><div><strong>${escapeHtml(person.displayName)}</strong><p class="meta">${escapeHtml(detail)}</p><p class="key">${shortKey(person.publicKey)}</p></div></a>`;
const restrictedDiscovery = () => renderRestrictedState("discovery");
const noDiscovery = () => renderEmptyState("friend-discovery");
const noConnections = () => renderEmptyState("connections");

function indexed(data) { return new Map(data.participants.map((person) => [person.id, person])); }
export function resolveViewer(viewerId, data = fixtureData) { return indexed(data).get(viewerId); }
export function selectViewer(currentViewerId, requestedViewerId, data = fixtureData) { return resolveViewer(requestedViewerId, data) ? requestedViewerId : currentViewerId; }

export function profileAccess({ viewer, viewerStatus, subjectId, participants, edges }) {
  if (!viewer || !validStatuses.has(viewerStatus)) return Object.freeze({ visible: false, reason: "restricted" });
  const subject = participants.find((person) => person.id === subjectId);
  if (!subject) return Object.freeze({ visible: false, reason: "restricted" });
  const context = relationshipContext(viewer.id, subject.id, edges);
  const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
  return decision.visible
    ? Object.freeze({ visible: true, subject, context })
    : Object.freeze({ visible: false, reason: "restricted" });
}

export function renderProfile({ viewer, viewerStatus, subjectId = viewer?.id, participants: people = fixtureData.participants, edges: graph = fixtureData.edges, statuses: access = fixtureData.statuses }) {
  const result = profileAccess({ viewer, viewerStatus, subjectId, participants: people, edges: graph });
  if (!result.visible) return renderRestrictedState("profile");
  const { subject, context } = result;
  const subjectStatus = validStatuses.has(access[subject.id]) ? access[subject.id] : "limited";
  const direct = context === RelationshipContext.DIRECT ? "Yes — direct social friend" : "No";
  const trustEdges = graph.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === subject.id || edge.to === subject.id));
  const trust = trustEdges.length ? `${trustEdges.length} external sponsor-trust relationship${trustEdges.length === 1 ? "" : "s"}` : "No fixture sponsor-trust relationships";
  return `<article class="profile-card"><div class="avatar avatar-large" aria-hidden="true">${escapeHtml(subject.displayName[0])}</div><h2>${escapeHtml(subject.displayName)}</h2>${renderStatusBadge(subjectStatus)}<p class="key">${shortKey(subject.publicKey)}</p><dl><div><dt>Relationship</dt><dd>${context}</dd></div><div><dt>Direct friend</dt><dd>${direct}</dd></div></dl><section class="trust-section"><h3>Sponsor-trust</h3><p>${trust}</p><p class="notice">Sponsor-trust is external provenance and remains separate from friendship.</p></section><p class="notice">Displayed role/status is externally derived and is not legal identity.</p></article>`;
}

export function renderFeed({ viewer, viewerStatus, participants, edges, notes, statuses: access = fixtureData.statuses }) {
  return renderSocialFeed({ viewer, viewerStatus, participants, edges, notes, statuses: access });
}

export function renderConnections({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return renderRestrictedState("connections");
  const rendered = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.DIRECT)
    .map(({ person, context }) => visibilityDecision({ viewerStatus, context, policy: "social" }).visible ? personCard(person, "Direct friend · social relationship") : renderRestrictedState("connections"))
    .join("");
  return rendered || noConnections();
}

export function renderDiscovery({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return restrictedDiscovery();
  const candidates = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) })).filter(({ context }) => context === RelationshipContext.FRIEND_OF_FRIEND);
  if (candidates.length === 0) return noDiscovery();
  if (!visibilityDecision({ viewerStatus, context: RelationshipContext.FRIEND_OF_FRIEND, policy: "social" }).visible) return restrictedDiscovery();
  return candidates.map(({ person }) => personCard(person, "Friend of friend · social relationship")).join("");
}

export function renderTrust({ viewer, viewerStatus, participants, edges }) {
  if (!viewer || !validStatuses.has(viewerStatus)) return renderRestrictedState("trust");
  const byId = new Map(participants.map((person) => [person.id, person]));
  const records = edges.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === viewer.id || edge.to === viewer.id));
  if (!records.length) return renderEmptyState("trust");
  return records.map((edge) => {
    const subject = byId.get(edge.from === viewer.id ? edge.to : edge.from);
    if (!subject) return renderRestrictedState("trust-record");
    const context = relationshipContext(viewer.id, subject.id, edges);
    return visibilityDecision({ viewerStatus, context, policy: "social" }).visible ? personCard(subject, "Sponsor-trust · external provenance") : renderRestrictedState("trust-record");
  }).join("");
}

export function renderPage(route, viewerId, data = fixtureData, ui = Object.freeze({})) {
  const viewer = resolveViewer(viewerId, data);
  const viewerStatus = viewer && validStatuses.has(data.statuses[viewer.id]) ? data.statuses[viewer.id] : undefined;
  const common = { viewer, viewerStatus, ...data };
  const headings = { home: "Home", search: "Search", discover: "Discover", circle: "My Circle", friends: "Friends", discovery: "Friends of Friends", messages: "Messages", groups: "Groups", notifications: "Notifications", activity: "Activity", profile: "Participant Profile", trust: "Trust" };
  let content;
  if (route.page === "home") return renderPageFrame({ title: "Home", content: renderHome(common, ui.reactions), className: "home-page" });
  else if (route.page === "search") content = renderSearch(common, route.searchQuery, route.queryValid);
  else if (route.page === "discover") content = renderLocalDiscovery(common);
  else if (route.page === "circle") content = renderCircle(common);
  else if (route.page === "friends") content = renderConnections(common);
  else if (route.page === "discovery") content = renderDiscovery(common);
  else if (route.page === "messages") content = renderMessages(common, route.localId, ui.messages);
  else if (route.page === "groups") content = renderGroups(common, route.localId);
  else if (route.page === "notifications") content = renderNotifications(common, ui.notificationState);
  else if (route.page === "activity") content = renderActivity(common, ui.reactions);
  else if (route.page === "profile") content = renderProfile({ ...common, subjectId: route.subjectId ?? viewer?.id });
  else if (route.page === "trust") content = `<article class="card trust-copy"><p><strong>${viewerStatus ?? "Restricted"} access</strong> · read-only external assertion</p><p>Social consumes HODLXXI runtime/CRT trust assertions; it does not issue or upgrade them.</p><p>Friendship does not prove covenant trust. No trust score is calculated.</p></article>${renderTrust(common)}`;
  else return renderPageFrame({ eyebrow: "Navigation", title: "Page unavailable", content: renderUnavailableState("route") });
  return renderPageFrame({ title: headings[route.page], content });
}

export function renderShell(viewerId, data = fixtureData, route = parseRoute("#/home"), ui = Object.freeze({})) {
  const viewer = resolveViewer(viewerId, data);
  const viewerStatus = viewer && validStatuses.has(data.statuses[viewer.id]) ? data.statuses[viewer.id] : undefined;
  const common = { viewer, viewerStatus, ...data };
  return Object.freeze({ viewerId: viewer?.id, viewerStatus, profile: renderProfile(common), feed: renderSocialFeed(common, ui.reactions), connections: renderConnections(common), discovery: renderDiscovery(common), trust: renderTrust(common), page: renderPage(route, viewerId, data, ui), navigation: renderNavigation(route, viewerId, "nav-links", visibleUnreadCount(common, ui.notificationState)) });
}

export function renderApp(root, data = fixtureData, browser = globalThis.window) {
  const selector = root.querySelector("#viewer-select");
  selector.innerHTML = data.participants.map((person) => `<option value="${person.id}">${escapeHtml(person.displayName)} · ${data.statuses[person.id]}</option>`).join("");
  let viewerId = resolveViewer(data.currentViewerId, data)?.id;
  let localNotes = [];
  let reactions = Object.freeze({});
  let localMessages = initializeLocalMessages(data.conversations);
  let notificationState = initializeNotificationState(data.notifications);
  const paint = () => {
    const route = parseRoute(browser?.location?.hash || "#/home");
    const activeData = { ...data, notes: [...localNotes, ...data.notes] };
    const shell = renderShell(viewerId, activeData, route, { reactions, messages: localMessages, notificationState });
    const unread = visibleUnreadCount({ viewer: resolveViewer(viewerId, activeData), viewerStatus: shell.viewerStatus, ...activeData }, notificationState);
    root.querySelector("#desktop-navigation").innerHTML = renderNavigation(route, viewerId, "nav-links", unread);
    root.querySelector("#mobile-navigation").innerHTML = renderNavigation(route, viewerId, "mobile-nav", unread);
    root.querySelector("#app-page").innerHTML = shell.page;
    root.querySelector("#context-profile").innerHTML = renderProfile({ viewer: resolveViewer(viewerId, data), viewerStatus: shell.viewerStatus, subjectId: viewerId, ...data });
    root.querySelector("#context-profile").parentElement.querySelector(".context-summary")?.remove();
    root.querySelector("#context-profile").insertAdjacentHTML("afterend", renderContextSummary({ viewer: resolveViewer(viewerId, data), viewerStatus: shell.viewerStatus, ...activeData }));
    root.querySelector("#access-mode").textContent = shell.viewerStatus ? `${shell.viewerStatus} access · read-only external assertion` : "Restricted · status unavailable";
    root.body?.setAttribute("data-access", shell.viewerStatus ?? "restricted");
  };
  selector.value = viewerId;
  selector.addEventListener("change", (event) => { viewerId = selectViewer(viewerId, event.target.value, data); localMessages = initializeLocalMessages(data.conversations); notificationState = initializeNotificationState(data.notifications); selector.value = viewerId; paint(); });
  root.addEventListener("submit", (event) => {
    if (event.target.id === "local-search") {
      event.preventDefault();
      const query = new FormData(event.target).get("q");
      const normalized = normalizeQuery(query);
      browser.location.hash = normalized ? `#/search?q=${encodeURIComponent(normalized)}` : "#/search";
      return;
    }
    if (event.target.id === "message-composer") {
      event.preventDefault();
      const formData = new FormData(event.target);
      const viewer = resolveViewer(viewerId, data);
      localMessages = appendLocalMessage(localMessages, { conversationId: formData.get("conversation"), viewer, viewerStatus: data.statuses[viewer?.id], participants: data.participants, edges: data.edges, body: formData.get("body") }, data.conversations);
      paint();
      return;
    }
    if (event.target.id !== "local-composer") return;
    event.preventDefault();
    const formData = new FormData(event.target);
    const viewer = resolveViewer(viewerId, data);
    const created = prependLocalPost(localNotes, { viewer, viewerStatus: data.statuses[viewer?.id], participants: data.participants, statuses: data.statuses, audience: formData.get("audience"), body: formData.get("body") });
    if (created.length > localNotes.length) localNotes = created;
    paint();
  });
  root.addEventListener("click", (event) => {
    const action = event.target.closest?.("[data-action]");
    if (action?.dataset.action === "mark-notification-read") {
      notificationState = markNotificationRead(notificationState, action.dataset.notification);
      paint();
      return;
    }
    if (action?.dataset.action === "mark-all-notifications-read") {
      notificationState = markAllNotificationsRead(notificationState);
      paint();
      return;
    }
    const button = event.target.closest?.('[data-action="react"]');
    if (!button) return;
    reactions = toggleReaction(reactions, button.dataset.note);
    paint();
  });
  browser?.addEventListener?.("hashchange", paint);
  paint();
}

if (typeof document !== "undefined") renderApp(document);
