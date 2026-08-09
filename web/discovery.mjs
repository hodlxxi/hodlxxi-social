import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { visibleFeed } from "./feed.mjs";
import { visibleGroups } from "./groups.mjs";

const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

export function deriveDiscovery(input) {
  if (!input.viewer) return Object.freeze({ people: Object.freeze([]), posts: Object.freeze([]), groups: Object.freeze([]) });
  const people = input.participants
    .filter((person) => relationshipContext(input.viewer.id, person.id, input.edges) === RelationshipContext.FRIEND_OF_FRIEND)
    .filter((person) => visibilityDecision({ viewerStatus: input.viewerStatus, context: relationshipContext(input.viewer.id, person.id, input.edges), policy: "social" }).visible)
    .sort((a, b) => a.id.localeCompare(b.id));
  const posts = visibleFeed(input).slice(0, 2);
  const groups = visibleGroups(input).map(({ group }) => group).sort((a, b) => a.id.localeCompare(b.id));
  return Object.freeze({ people: Object.freeze(people), posts: Object.freeze(posts), groups: Object.freeze(groups) });
}

export function renderLocalDiscovery(input) {
  const suggestions = deriveDiscovery(input);
  const byId = new Map(input.participants.map((person) => [person.id, person]));
  const people = suggestions.people.map((person) => `<a class="discovery-card" href="#/profile/${person.id}"><strong>${escapeHtml(person.displayName)}</strong><span>Permitted friend of friend</span></a>`).join("");
  const posts = suggestions.posts.map((post) => `<a class="discovery-card" href="#/home"><strong>${escapeHtml(byId.get(post.authorId)?.displayName ?? "Visible participant")}</strong><span>${escapeHtml(post.body)}</span></a>`).join("");
  const groups = suggestions.groups.map((group) => `<a class="discovery-card" href="#/groups/${group.id}"><strong>${escapeHtml(group.title)}</strong><span>${escapeHtml(group.description)}</span></a>`).join("");
  const empty = '<p class="search-none">No permitted local suggestions in this category.</p>';
  return `<section class="discovery-product"><div class="local-disclosure"><strong>Local synthetic discovery</strong><span>Deterministic fixture suggestions for this viewer.</span></div><div class="discovery-grid"><section><h2>People in reach</h2>${people || empty}</section><section><h2>Accessible groups</h2>${groups || empty}</section><section><h2>Recent visible posts</h2>${posts || empty}</section></div><p class="notice">Discovery is not personalized ML, a live network trend, a popularity measure, or a trust score. Friendship and group membership cannot grant covenant status or authority.</p></section>`;
}
