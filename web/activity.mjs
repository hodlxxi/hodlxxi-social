import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { visibleFeed } from "./feed.mjs";
import { visibleConversations } from "./messages.mjs";
import { visibleGroups } from "./groups.mjs";

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

export function deriveActivity(input, reactions = Object.freeze({})) {
  if (!input.viewer) return Object.freeze([]);
  const posts = visibleFeed(input);
  const visiblePostIds = new Set(posts.map((post) => post.id));
  const friends = input.participants.filter((person) => relationshipContext(input.viewer.id, person.id, input.edges) === RelationshipContext.DIRECT)
    .filter((person) => visibilityDecision({ viewerStatus: input.viewerStatus, context: RelationshipContext.DIRECT, policy: "social" }).visible);
  const conversations = visibleConversations(input);
  const groups = visibleGroups(input);
  const localReactions = Object.entries(reactions).filter(([id, active]) => active && visiblePostIds.has(id)).length;
  return Object.freeze([
    Object.freeze({ label: "Recent posts", value: posts.length, detail: "Visible synthetic fixture and in-memory posts" }),
    Object.freeze({ label: "Your reactions", value: localReactions, detail: "Current in-memory reaction choices" }),
    Object.freeze({ label: "Direct-friend activity", value: friends.length, detail: "Policy-permitted local social connections" }),
    Object.freeze({ label: "Messages", value: conversations.length, detail: "Accessible synthetic local conversations" }),
    Object.freeze({ label: "Groups", value: groups.length, detail: "Accessible read-only local group fixtures" })
  ]);
}

export function renderActivity(input, reactions = Object.freeze({})) {
  const rows = deriveActivity(input, reactions).map((item) => `<article class="activity-row"><span>${escapeHtml(item.value)}</span><div><strong>${escapeHtml(item.label)}</strong><p>${escapeHtml(item.detail)}</p></div></article>`).join("");
  return `<section class="activity-product"><div class="local-disclosure"><strong>Local synthetic activity</strong><span>A private summary of this browser demo, not live network telemetry.</span></div><div class="activity-list">${rows || `<article class="activity-row"><div><strong>Activity unavailable</strong><p>No viewer-scoped local summary is available.</p></div></article>`}</div><p class="notice">Counts are local demo summaries, not active-user, transaction, trust, or reputation scores. Posts, reactions, friendship, messaging, and groups cannot change externally derived CRT status or grant Operator authority.</p></section>`;
}
