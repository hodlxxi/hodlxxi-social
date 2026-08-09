import { participants, statuses, edges, notes } from "../src/fixtures.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";

const viewer = participants[1];

const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;

const personCard = (person, detail) => `<article class="person"><div class="avatar">${person.displayName[0]}</div><div><strong>${person.displayName}</strong><p class="meta">${detail}</p><p class="key">${shortKey(person.publicKey)}</p></div></article>`;
const restrictedDirectConnection = () => '<article class="person restricted"><div><strong>Restricted connection</strong><p class="meta">Direct connection details are unavailable for this access level.</p></div></article>';
const restrictedDiscovery = () => '<article class="person restricted"><div><strong>Restricted connection</strong><p class="meta">Friend-of-friend discovery is unavailable for Limited access.</p></div></article>';
const noDiscovery = () => '<article class="person restricted"><div><strong>No discoverable connections</strong><p class="meta">No friend-of-friend participants are available under the social visibility policy.</p></div></article>';

export function renderConnections({ viewer, viewerStatus, participants, edges }) {
  return participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.DIRECT)
    .map(({ person, context }) => {
      const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
      if (!decision.visible) return restrictedDirectConnection();
      return personCard(person, "Direct friend");
    })
    .join("");
}

export function renderDiscovery({ viewer, viewerStatus, participants, edges }) {
  const rendered = participants.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }))
    .filter(({ context }) => context === RelationshipContext.FRIEND_OF_FRIEND)
    .map(({ person, context }) => {
      const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
      if (!decision.visible) return restrictedDiscovery();
      return personCard(person, "Friend of friend");
    })
    .join("");
  return rendered || noDiscovery();
}

export function renderApp(root) {
  const byId = new Map(participants.map((item) => [item.id, item]));
  const viewerStatus = statuses[viewer.id];
  root.querySelector("#profile").innerHTML = `<div class="avatar">${viewer.displayName[0]}</div><h2>${viewer.displayName}</h2><span class="badge">${viewerStatus}</span><p class="key">${viewer.publicKey}</p>`;
  root.querySelector("#feed").innerHTML = notes.map((note) => {
    const context = relationshipContext(viewer.id, note.authorId, edges);
    const decision = visibilityDecision({ viewerStatus, context, policy: "social" });
    return decision.visible ? `<article class="card"><span class="badge">${statuses[note.authorId]}</span><p>${note.body}</p><p class="meta">${byId.get(note.authorId).displayName} · ${context}</p></article>` : `<article class="card restricted"><strong>Content restricted</strong><p class="meta">Visibility policy: ${decision.reason}</p></article>`;
  }).join("");
  root.querySelector("#connections").innerHTML = renderConnections({ viewer, viewerStatus, participants, edges });
  root.querySelector("#discovery").innerHTML = renderDiscovery({ viewer, viewerStatus, participants, edges });
}

if (typeof document !== "undefined") renderApp(document);
