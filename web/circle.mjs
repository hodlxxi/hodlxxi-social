import { AccessStatus, EdgeType } from "../src/domain.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";

const statusValues = new Set(Object.values(AccessStatus));
const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const profileRoute = (id) => `#/profile/${id}`;

export function ringLayout(items, { centerX = 400, centerY = 260, radius = 130, startAngle = -Math.PI / 2 } = {}) {
  return Object.freeze(items.map((item, index) => {
    const angle = startAngle + (Math.PI * 2 * index) / Math.max(items.length, 1);
    return Object.freeze({ ...item, x: Number((centerX + Math.cos(angle) * radius).toFixed(3)), y: Number((centerY + Math.sin(angle) * radius).toFixed(3)) });
  }));
}

export function deriveCircleGraph({ viewer, viewerStatus, participants = [], edges = [] }) {
  if (!viewer || !statusValues.has(viewerStatus) || !participants.some((person) => person.id === viewer.id)) {
    return Object.freeze({ available: false, nodes: Object.freeze([]), socialEdges: Object.freeze([]), trustEdges: Object.freeze([]), summary: Object.freeze({ direct: 0, visibleReach: 0, restrictedReach: 0, sponsorTrust: 0 }) });
  }

  const candidates = participants.filter((person) => person.id !== viewer.id).sort((a, b) => a.id.localeCompare(b.id));
  const classified = candidates.map((person) => ({ person, context: relationshipContext(viewer.id, person.id, edges) }));
  const directPeople = classified.filter(({ context }) => context === RelationshipContext.DIRECT)
    .filter(({ context }) => visibilityDecision({ viewerStatus, context, policy: "social" }).visible)
    .map(({ person }) => person);
  const reach = classified.filter(({ context }) => context === RelationshipContext.FRIEND_OF_FRIEND);
  const visibleReach = reach.filter(({ context }) => visibilityDecision({ viewerStatus, context, policy: "social" }).visible).map(({ person }) => person);
  const restrictedReach = reach.length - visibleReach.length;

  const center = Object.freeze({ kind: "viewer", ring: "center", person: viewer, x: 400, y: 260 });
  const inner = ringLayout(directPeople.map((person) => ({ kind: "participant", ring: "inner", person })), { radius: 130 });
  const outerItems = visibleReach.map((person) => ({ kind: "participant", ring: "outer", person }));
  if (restrictedReach) outerItems.push({ kind: "restricted", ring: "outer", count: restrictedReach });
  const outer = ringLayout(outerItems, { radius: 220 });
  const nodes = Object.freeze([center, ...inner, ...outer]);
  const positioned = new Map(nodes.filter((node) => node.person).map((node) => [node.person.id, node]));
  const socialEdges = Object.freeze(edges.filter((edge) => edge.type === EdgeType.FRIEND && positioned.has(edge.from) && positioned.has(edge.to))
    .map((edge) => Object.freeze({ type: "friend", from: positioned.get(edge.from), to: positioned.get(edge.to) })));
  const associatedTrust = edges.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === viewer.id || edge.to === viewer.id));
  const trustEdges = Object.freeze(associatedTrust.map((edge) => {
    const otherId = edge.from === viewer.id ? edge.to : edge.from;
    const target = positioned.get(otherId);
    return Object.freeze(target
      ? { type: "sponsor-trust", from: center, to: target, restricted: false }
      : { type: "sponsor-trust", from: center, to: Object.freeze({ x: 690, y: 70 }), restricted: true });
  }));

  return Object.freeze({
    available: true,
    nodes,
    socialEdges,
    trustEdges,
    summary: Object.freeze({ direct: inner.length, visibleReach: visibleReach.length, restrictedReach, sponsorTrust: associatedTrust.length })
  });
}

const line = (edge, className) => `<line class="${className}" x1="${edge.from.x}" y1="${edge.from.y}" x2="${edge.to.x}" y2="${edge.to.y}" />`;

function participantNode(node) {
  const { person } = node;
  const label = escapeHtml(person.displayName);
  return `<a class="circle-node-link" href="${profileRoute(person.id)}" aria-label="Open ${label} profile"><g class="circle-node circle-node-${node.ring}" transform="translate(${node.x} ${node.y})"><circle r="${node.ring === "center" ? 44 : 34}"/><text class="circle-initial" text-anchor="middle" y="6">${escapeHtml(person.displayName[0])}</text><text class="circle-label" text-anchor="middle" y="${node.ring === "center" ? 66 : 54}">${label}</text></g></a>`;
}

function restrictedNode(node) {
  return `<g class="circle-node circle-node-restricted" transform="translate(${node.x} ${node.y})" aria-label="Restricted reach"><circle r="34"/><text text-anchor="middle" y="5">•••</text><text class="circle-label" text-anchor="middle" y="54">Restricted reach</text></g>`;
}

export function renderCircle({ viewer, viewerStatus, participants, edges }) {
  const graph = deriveCircleGraph({ viewer, viewerStatus, participants, edges });
  if (!graph.available) return '<article class="circle-restricted restricted"><strong>Circle unavailable</strong><p class="meta">A valid synthetic viewer and access assertion are required.</p></article>';
  const trustMarkers = graph.trustEdges.filter((edge) => edge.restricted).map((edge) => `<g class="trust-marker" transform="translate(${edge.to.x} ${edge.to.y})" aria-label="Restricted sponsor-trust relation"><rect x="-54" y="-18" width="108" height="36" rx="18"/><text text-anchor="middle" y="5">Sponsor-trust</text></g>`).join("");
  const nodes = graph.nodes.map((node) => node.kind === "restricted" ? restrictedNode(node) : participantNode(node)).join("");
  const { direct, visibleReach, restrictedReach, sponsorTrust } = graph.summary;
  return `<section class="circle-product"><div class="circle-heading"><div><p class="eyebrow">Local social topology</p><h2>Your people, in context</h2><p>Friendship maps social reach. Sponsor-trust is separate external provenance; friendship does not prove covenant trust.</p></div><span class="local-pill">Synthetic fixture</span></div><div class="circle-canvas"><svg class="circle-graph" viewBox="0 0 800 520" role="img" aria-labelledby="circle-title circle-description"><title id="circle-title">My Circle social topology</title><desc id="circle-description">The current participant is centered, direct friends form the inner circle, and visible friends of friends form the outer circle. Sponsor-trust uses dashed lines and does not create social reach.</desc><circle class="ring-guide ring-guide-outer" cx="400" cy="260" r="220"/><circle class="ring-guide ring-guide-inner" cx="400" cy="260" r="130"/>${graph.socialEdges.map((edge) => line(edge, "friend-edge")).join("")}${graph.trustEdges.map((edge) => line(edge, "trust-edge")).join("")}${nodes}${trustMarkers}</svg></div><div class="circle-legend" aria-label="Relationship legend"><span><i class="legend-friend"></i>Friend · social relationship</span><span><i class="legend-trust"></i>Sponsor-trust · external provenance</span><span><i class="legend-reach"></i>Outer ring · friend of friend</span></div><dl class="circle-summary"><div><dt>Direct friends</dt><dd>${direct}</dd></div><div><dt>Visible friend-of-friend</dt><dd>${visibleReach}</dd></div><div><dt>Restricted reach</dt><dd>${restrictedReach}</dd></div><div><dt>Sponsor-trust relations</dt><dd>${sponsorTrust}</dd></div></dl><p class="notice">Local synthetic fixture summary only. Not live network activity, covenant status, or a trust score.</p></section>`;
}
