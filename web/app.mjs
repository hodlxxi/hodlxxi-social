import { EdgeType } from "../src/domain.mjs";
import { participants, statuses, edges, notes } from "../src/fixtures.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";

const fixtureData = Object.freeze({ participants, statuses, edges, notes });
const validStatuses = new Set(["limited", "full", "operator"]);

export const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;

const personCard = (person, detail) => `<article class="person"><div class="avatar" aria-hidden="true">${person.displayName[0]}</div><div><strong>${person.displayName}</strong><p class="meta">${detail}</p><p class="key">${shortKey(person.publicKey)}</p></div></article>`;
const restrictedCard = (title, detail) => `<article class="person restricted"><div><strong>${title}</strong><p class="meta">${detail}</p></div></article>`;
const restrictedDiscovery = () => restrictedCard("Restricted connection", "Friend-of-friend discovery is unavailable for this access level.");
const noDiscovery = () => restrictedCard("No discoverable connections", "No friend-of-friend participants are available under the social visibility policy.");
const noConnections = () => restrictedCard("No direct connections", "No direct friends are available under the social visibility policy.");

function indexed(data) {
  return new Map(data.participants.map((person) => [person.id, person]));
}

export function resolveViewer(viewerId, data = fixtureData) {
  return indexed(data).get(viewerId);
}

export function selectViewer(currentViewerId, requestedViewerId, data = fixtureData) {
  return resolveViewer(requestedViewerId, data) ? requestedViewerId : currentViewerId;
}

export function renderProfile({ viewer, viewerStatus }) {
  if (!viewer || !validStatuses.has(viewerStatus)) {
    return restrictedCard("Viewer unavailable", "Access status is unavailable; social details are hidden by default.");
  }
  return `<div class="avatar avatar-large" aria-hidden="true">${viewer.displayName[0]}</div><h2>${viewer.displayName}</h2><span class="badge badge-${viewerStatus}">${viewerStatus}</span><p class="key">${shortKey(viewer.publicKey)}</p><p class="notice">Displayed status is externally derived and is not legal identity.</p>`;
}

export function renderFeed({ viewer, viewerStatus, participants, edges, notes }) {
  const byId = new Map(participants.map((person) => [person.id, person]));
  return notes.map((note) => {
    const author = byId.get(note.authorId);
    if (!viewer || !author) return restrictedCard("Content restricted", "This item is unavailable under the social visibility policy.");
    const context = relationshipContext(viewer.id, author.id, edges);
    const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
    if (!decision.visible) return restrictedCard("Content restricted", "This item is unavailable under the social visibility policy.");
    return `<article class="card"><span class="badge badge-${viewerStatus}">${context}</span><p>${note.body}</p><p class="meta">${author.displayName} · ${shortKey(author.publicKey)}</p></article>`;
  }).join("");
}

export function renderConnections({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return restrictedCard("Connections restricted", "Direct connection details are unavailable.");
  const rendered = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.DIRECT)
    .map(({ person, context }) => visibilityDecision({ viewerStatus, context, policy: "social" }).visible
      ? personCard(person, "Direct friend · social relationship")
      : restrictedCard("Restricted connection", "Direct connection details are unavailable for this access level."))
    .join("");
  return rendered || noConnections();
}

export function renderDiscovery({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return restrictedDiscovery();
  const candidates = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.FRIEND_OF_FRIEND);
  if (candidates.length === 0) return noDiscovery();
  const decision = visibilityDecision({ viewerStatus, context: RelationshipContext.FRIEND_OF_FRIEND, policy: "social" });
  if (!decision.visible) return restrictedDiscovery();
  return candidates.map(({ person }) => personCard(person, "Friend of friend · social relationship")).join("");
}

export function renderTrust({ viewer, viewerStatus, participants, edges }) {
  if (!viewer) return restrictedCard("Trust records restricted", "Sponsor-trust details are unavailable.");
  const byId = new Map(participants.map((person) => [person.id, person]));
  const records = edges.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === viewer.id || edge.to === viewer.id));
  if (records.length === 0) return restrictedCard("No associated trust records", "Sponsor-trust is external provenance, not a friend connection.");
  return records.map((edge) => {
    const subject = byId.get(edge.from === viewer.id ? edge.to : edge.from);
    if (!subject) return restrictedCard("Trust record restricted", "Sponsor-trust details are unavailable.");
    const context = relationshipContext(viewer.id, subject.id, edges);
    const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
    return decision.visible
      ? personCard(subject, "Sponsor-trust · external provenance")
      : restrictedCard("Trust record restricted", "An associated sponsor-trust record exists, but its participant identity is not visible under social policy.");
  }).join("");
}

export function renderShell(viewerId, data = fixtureData) {
  const viewer = resolveViewer(viewerId, data);
  const viewerStatus = viewer ? data.statuses[viewer.id] : undefined;
  return Object.freeze({
    viewerId: viewer?.id,
    viewerStatus: validStatuses.has(viewerStatus) ? viewerStatus : undefined,
    profile: renderProfile({ viewer, viewerStatus }),
    feed: renderFeed({ viewer, viewerStatus, ...data }),
    connections: renderConnections({ viewer, viewerStatus, ...data }),
    discovery: renderDiscovery({ viewer, viewerStatus, ...data }),
    trust: renderTrust({ viewer, viewerStatus, ...data })
  });
}

export function renderApp(root, data = fixtureData) {
  const selector = root.querySelector("#viewer-select");
  selector.innerHTML = data.participants.map((person) => `<option value="${person.id}">${person.displayName} · ${data.statuses[person.id]}</option>`).join("");
  let viewerId = data.participants[1]?.id ?? data.participants[0]?.id;

  const paint = () => {
    const shell = renderShell(viewerId, data);
    root.querySelector("#profile").innerHTML = shell.profile;
    root.querySelector("#feed").innerHTML = shell.feed;
    root.querySelector("#connections").innerHTML = shell.connections;
    root.querySelector("#discovery").innerHTML = shell.discovery;
    root.querySelector("#trust").innerHTML = shell.trust;
    root.querySelector("#access-mode").textContent = shell.viewerStatus
      ? `${shell.viewerStatus} access · read-only external assertion`
      : "Restricted · status unavailable";
    root.body?.setAttribute("data-access", shell.viewerStatus ?? "restricted");
  };

  selector.value = viewerId;
  selector.addEventListener("change", (event) => {
    const selected = selectViewer(viewerId, event.target.value, data);
    viewerId = selected;
    selector.value = selected;
    paint();
  });
  paint();
}

if (typeof document !== "undefined") renderApp(document);
