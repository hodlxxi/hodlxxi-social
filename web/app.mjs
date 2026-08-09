import { EdgeType } from "../src/domain.mjs";
import { participants, statuses, edges, notes } from "../src/fixtures.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { prependLocalPost, renderContextSummary, renderFeed as renderSocialFeed, renderHome, toggleReaction } from "./feed.mjs";
import { renderCircle } from "./circle.mjs";

const fixtureData = Object.freeze({ participants, statuses, edges, notes });
const validStatuses = new Set(["limited", "full", "operator"]);
const pageRoutes = Object.freeze({ home: "/home", circle: "/circle", friends: "/friends", discovery: "/friends-of-friends", trust: "/trust" });
const navigation = Object.freeze([
  ["home", "Home"], ["circle", "My Circle"], ["friends", "Friends"],
  ["discovery", "Friends of Friends"], ["profile", "Profile"], ["trust", "Trust"]
]);

export const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;
export const profileRoute = (subjectId) => `#/profile/${subjectId}`;

export function parseRoute(hash = "") {
  const value = typeof hash === "string" ? hash : "";
  const path = value.startsWith("#") ? value.slice(1) : value;
  const page = Object.entries(pageRoutes).find(([, route]) => route === path)?.[0];
  if (page) return Object.freeze({ page, path });
  const match = path.match(/^\/profile\/([0-9a-fA-F]{64})$/);
  if (match) return Object.freeze({ page: "profile", path, subjectId: match[1].toLowerCase() });
  return Object.freeze({ page: "not-found", path: "/not-found" });
}

export function routeFor(page, viewerId) {
  if (page === "profile") return profileRoute(viewerId);
  return `#${pageRoutes[page] ?? "/not-found"}`;
}

const personCard = (person, detail) => `<a class="person person-link" href="${profileRoute(person.id)}"><div class="avatar" aria-hidden="true">${person.displayName[0]}</div><div><strong>${person.displayName}</strong><p class="meta">${detail}</p><p class="key">${shortKey(person.publicKey)}</p></div></a>`;
const restrictedCard = (title, detail) => `<article class="person restricted"><div><strong>${title}</strong><p class="meta">${detail}</p></div></article>`;
const restrictedDiscovery = () => restrictedCard("Restricted connection", "Friend-of-friend discovery is unavailable for this access level.");
const noDiscovery = () => restrictedCard("No discoverable connections", "No friend-of-friend participants are available under the social visibility policy.");
const noConnections = () => restrictedCard("No direct connections", "No direct friends are available under the social visibility policy.");

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
  if (!result.visible) return restrictedCard("Profile restricted", "This participant profile is unavailable under the social visibility policy.");
  const { subject, context } = result;
  const subjectStatus = validStatuses.has(access[subject.id]) ? access[subject.id] : "limited";
  const direct = context === RelationshipContext.DIRECT ? "Yes — direct social friend" : "No";
  const trustEdges = graph.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === subject.id || edge.to === subject.id));
  const trust = trustEdges.length ? `${trustEdges.length} external sponsor-trust relationship${trustEdges.length === 1 ? "" : "s"}` : "No fixture sponsor-trust relationships";
  return `<article class="profile-card"><div class="avatar avatar-large" aria-hidden="true">${subject.displayName[0]}</div><h1>${subject.displayName}</h1><span class="badge badge-${subjectStatus}">${subjectStatus}</span><p class="key">${shortKey(subject.publicKey)}</p><dl><div><dt>Relationship</dt><dd>${context}</dd></div><div><dt>Direct friend</dt><dd>${direct}</dd></div></dl><section class="trust-section"><h2>Sponsor-trust</h2><p>${trust}</p><p class="notice">Sponsor-trust is external provenance and remains separate from friendship.</p></section><p class="notice">Displayed role/status is externally derived and is not legal identity.</p></article>`;
}

export function renderFeed({ viewer, viewerStatus, participants, edges, notes, statuses: access = fixtureData.statuses }) {
  return renderSocialFeed({ viewer, viewerStatus, participants, edges, notes, statuses: access });
}

export function renderConnections({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return restrictedCard("Connections restricted", "Direct connection details are unavailable.");
  const rendered = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.DIRECT)
    .map(({ person, context }) => visibilityDecision({ viewerStatus, context, policy: "social" }).visible ? personCard(person, "Direct friend · social relationship") : restrictedCard("Restricted connection", "Direct connection details are unavailable for this access level."))
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
  if (!viewer || !validStatuses.has(viewerStatus)) return restrictedCard("Trust records restricted", "Sponsor-trust details are unavailable.");
  const byId = new Map(participants.map((person) => [person.id, person]));
  const records = edges.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === viewer.id || edge.to === viewer.id));
  if (!records.length) return restrictedCard("No associated trust records", "Sponsor-trust is external provenance, not a friend connection.");
  return records.map((edge) => {
    const subject = byId.get(edge.from === viewer.id ? edge.to : edge.from);
    if (!subject) return restrictedCard("Trust record restricted", "Sponsor-trust details are unavailable.");
    const context = relationshipContext(viewer.id, subject.id, edges);
    return visibilityDecision({ viewerStatus, context, policy: "social" }).visible ? personCard(subject, "Sponsor-trust · external provenance") : restrictedCard("Trust record restricted", "An associated sponsor-trust record exists, but its participant identity is not visible under social policy.");
  }).join("");
}

export function renderNavigation(route, viewerId, className = "nav-links") {
  return `<nav class="${className}" aria-label="${className === "mobile-nav" ? "Mobile" : "Primary"}">${navigation.map(([page, label]) => {
    const href = routeFor(page, viewerId);
    return `<a href="${href}"${route.page === page ? ' aria-current="page"' : ""}>${label}</a>`;
  }).join("")}</nav>`;
}

export function renderPage(route, viewerId, data = fixtureData, ui = Object.freeze({})) {
  const viewer = resolveViewer(viewerId, data);
  const viewerStatus = viewer && validStatuses.has(data.statuses[viewer.id]) ? data.statuses[viewer.id] : undefined;
  const common = { viewer, viewerStatus, ...data };
  const headings = { home: "Home", circle: "My Circle", friends: "Friends", discovery: "Friends of Friends", profile: "Participant Profile", trust: "Trust" };
  let content;
  if (route.page === "home") return `<section class="page home-page">${renderHome(common, ui.reactions)}</section>`;
  else if (route.page === "circle") content = renderCircle(common);
  else if (route.page === "friends") content = renderConnections(common);
  else if (route.page === "discovery") content = renderDiscovery(common);
  else if (route.page === "profile") content = renderProfile({ ...common, subjectId: route.subjectId ?? viewer?.id });
  else if (route.page === "trust") content = `<article class="card trust-copy"><p><strong>${viewerStatus ?? "Restricted"} access</strong> · read-only external assertion</p><p>Social consumes HODLXXI runtime/CRT trust assertions; it does not issue or upgrade them.</p><p>Friendship does not prove covenant trust. No trust score is calculated.</p></article>${renderTrust(common)}`;
  else return `<section class="page"><p class="eyebrow">Navigation</p><h1>Page unavailable</h1>${restrictedCard("Route not found", "Use the application navigation to choose a local surface.")}</section>`;
  return `<section class="page"><p class="eyebrow">HODLXXI Social</p><h1>${headings[route.page]}</h1>${content}</section>`;
}

export function renderShell(viewerId, data = fixtureData, route = parseRoute("#/home"), ui = Object.freeze({})) {
  const viewer = resolveViewer(viewerId, data);
  const viewerStatus = viewer && validStatuses.has(data.statuses[viewer.id]) ? data.statuses[viewer.id] : undefined;
  const common = { viewer, viewerStatus, ...data };
  return Object.freeze({ viewerId: viewer?.id, viewerStatus, profile: renderProfile(common), feed: renderSocialFeed(common, ui.reactions), connections: renderConnections(common), discovery: renderDiscovery(common), trust: renderTrust(common), page: renderPage(route, viewerId, data, ui), navigation: renderNavigation(route, viewerId) });
}

export function renderApp(root, data = fixtureData, browser = globalThis.window) {
  const selector = root.querySelector("#viewer-select");
  selector.innerHTML = data.participants.map((person) => `<option value="${person.id}">${person.displayName} · ${data.statuses[person.id]}</option>`).join("");
  let viewerId = data.participants[1]?.id ?? data.participants[0]?.id;
  let localNotes = [];
  let reactions = Object.freeze({});
  const paint = () => {
    const route = parseRoute(browser?.location?.hash || "#/home");
    const activeData = { ...data, notes: [...localNotes, ...data.notes] };
    const shell = renderShell(viewerId, activeData, route, { reactions });
    root.querySelector("#desktop-navigation").innerHTML = renderNavigation(route, viewerId);
    root.querySelector("#mobile-navigation").innerHTML = renderNavigation(route, viewerId, "mobile-nav");
    root.querySelector("#app-page").innerHTML = shell.page;
    root.querySelector("#context-profile").innerHTML = renderProfile({ viewer: resolveViewer(viewerId, data), viewerStatus: shell.viewerStatus, subjectId: viewerId, ...data });
    root.querySelector("#context-profile").parentElement.querySelector(".context-summary")?.remove();
    root.querySelector("#context-profile").insertAdjacentHTML("afterend", renderContextSummary({ viewer: resolveViewer(viewerId, data), viewerStatus: shell.viewerStatus, ...activeData }));
    root.querySelector("#access-mode").textContent = shell.viewerStatus ? `${shell.viewerStatus} access · read-only external assertion` : "Restricted · status unavailable";
    root.body?.setAttribute("data-access", shell.viewerStatus ?? "restricted");
  };
  selector.value = viewerId;
  selector.addEventListener("change", (event) => { viewerId = selectViewer(viewerId, event.target.value, data); selector.value = viewerId; paint(); });
  root.addEventListener("submit", (event) => {
    if (event.target.id !== "local-composer") return;
    event.preventDefault();
    const formData = new FormData(event.target);
    const viewer = resolveViewer(viewerId, data);
    const created = prependLocalPost(localNotes, { viewer, viewerStatus: data.statuses[viewer?.id], participants: data.participants, statuses: data.statuses, audience: formData.get("audience"), body: formData.get("body") });
    if (created.length > localNotes.length) localNotes = created;
    paint();
  });
  root.addEventListener("click", (event) => {
    const button = event.target.closest?.('[data-action="react"]');
    if (!button) return;
    reactions = toggleReaction(reactions, button.dataset.note);
    paint();
  });
  browser?.addEventListener?.("hashchange", paint);
  paint();
}

if (typeof document !== "undefined") renderApp(document);
