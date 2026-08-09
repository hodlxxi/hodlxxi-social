import { AccessStatus, EdgeType } from "../src/domain.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";

export const Audience = Object.freeze({ PUBLIC: "PUBLIC", FULL_NETWORK: "FULL_NETWORK", FRIENDS: "FRIENDS" });
const audienceValues = new Set(Object.values(Audience));
const statusValues = new Set(Object.values(AccessStatus));
const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const profileRoute = (id) => `#/profile/${id}`;

function validViewer({ viewer, viewerStatus, participants, statuses }) {
  return Boolean(viewer && Array.isArray(participants) && participants.some((person) => person.id === viewer.id) && statusValues.has(viewerStatus) && statuses?.[viewer.id] === viewerStatus);
}

export function audienceDecision({ audience, viewerStatus, context }) {
  if (!audienceValues.has(audience) || !statusValues.has(viewerStatus) || !Object.values(RelationshipContext).includes(context)) return Object.freeze({ visible: false, reason: "deny-by-default" });
  if (!visibilityDecision({ viewerStatus, context, policy: "social" }).visible) return Object.freeze({ visible: false, reason: "social-policy" });
  if (audience === Audience.FULL_NETWORK) return Object.freeze({ visible: viewerStatus === AccessStatus.FULL || viewerStatus === AccessStatus.OPERATOR, reason: "local-full-network" });
  if (audience === Audience.FRIENDS) return Object.freeze({ visible: context === RelationshipContext.SELF || context === RelationshipContext.DIRECT, reason: "local-friends" });
  return Object.freeze({ visible: true, reason: "local-public" });
}

export function visibleFeed({ viewer, viewerStatus, participants, statuses, edges, notes }) {
  if (!validViewer({ viewer, viewerStatus, participants, statuses })) return Object.freeze([]);
  const people = new Map(participants.map((person) => [person.id, person]));
  return Object.freeze(notes.filter((note) => {
    const author = people.get(note.authorId);
    if (!author || !statusValues.has(statuses?.[author.id])) return false;
    return audienceDecision({ audience: note.audience, viewerStatus, context: relationshipContext(viewer.id, author.id, edges) }).visible;
  }));
}

export function prependLocalPost(notes, { viewer, viewerStatus, participants, statuses, audience, body, timestamp = "Just now · local" }) {
  if (!validViewer({ viewer, viewerStatus, participants, statuses }) || !audienceValues.has(audience) || typeof body !== "string" || !body.trim()) return Object.freeze([...notes]);
  const post = Object.freeze({ id: `local-${notes.length + 1}`, authorId: viewer.id, audience, body: body.trim(), timestamp, reactions: 0, comments: 0, reposts: 0, replies: Object.freeze([]), local: true });
  return Object.freeze([post, ...notes]);
}

export function toggleReaction(state = Object.freeze({}), noteId) {
  if (typeof noteId !== "string" || !noteId) return Object.freeze({ ...state });
  return Object.freeze({ ...state, [noteId]: !state[noteId] });
}

function renderReplies(note, common, people) {
  const replies = (note.replies ?? []).flatMap((reply) => {
    const author = people.get(reply.authorId);
    if (!author || !statusValues.has(common.statuses?.[author.id])) return [];
    const context = relationshipContext(common.viewer.id, author.id, common.edges);
    if (!visibilityDecision({ viewerStatus: common.viewerStatus, context, policy: "social" }).visible) return [];
    return [`<li><a href="${profileRoute(author.id)}">${escapeHtml(author.displayName)}</a><p>${escapeHtml(reply.body)}</p></li>`];
  });
  return replies.length ? `<section class="replies" aria-label="Visible local replies"><strong>Replies</strong><ul>${replies.join("")}</ul></section>` : "";
}

export function renderComposer({ viewer, viewerStatus, participants, statuses }) {
  if (!validViewer({ viewer, viewerStatus, participants, statuses })) return '<article class="restricted composer-restricted"><strong>Composer unavailable</strong><p class="meta">A valid synthetic viewer is required.</p></article>';
  return `<form class="composer-card" id="local-composer"><div class="composer-head"><div class="avatar" aria-hidden="true">${escapeHtml(viewer.displayName[0])}</div><div><strong>${escapeHtml(viewer.displayName)}</strong><span class="badge badge-${viewerStatus}">${viewerStatus}</span><p class="meta">Local demo composer · resets on reload</p></div></div><label class="sr-only" for="composer-body">Write a local demo post</label><textarea id="composer-body" name="body" maxlength="500" placeholder="Share something with your network…" required></textarea><div class="composer-actions"><div class="local-tools" aria-label="Local demo affordances"><span>Media</span><span>Poll</span><span>Emoji</span></div><label>Audience <select name="audience">${Object.values(Audience).map((value) => `<option value="${value}">${value.replace("_", " ")}</option>`).join("")}</select></label><button type="submit">Post locally</button></div><p class="notice">Audience is a local presentation filter, not Nostr publication policy. Nothing is signed or broadcast.</p></form>`;
}

export function renderFeed(common, reactionState = Object.freeze({})) {
  const people = new Map(common.participants.map((person) => [person.id, person]));
  const feed = visibleFeed(common);
  if (!feed.length) return '<article class="restricted"><strong>No visible local posts</strong><p class="meta">The local audience and social visibility policies fail closed.</p></article>';
  return feed.map((note) => {
    const author = people.get(note.authorId);
    const authorStatus = common.statuses[author.id];
    const reacted = Boolean(reactionState[note.id]);
    const media = note.media ? `<div class="media-placeholder" role="img" aria-label="${escapeHtml(note.media)}"><span>${escapeHtml(note.media)}</span></div>` : "";
    return `<article class="post-card" data-note-id="${escapeHtml(note.id)}"><header><div class="avatar" aria-hidden="true">${escapeHtml(author.displayName[0])}</div><div><a class="post-author" href="${profileRoute(author.id)}">${escapeHtml(author.displayName)}</a><span class="badge badge-${authorStatus}">${authorStatus}</span><p class="post-meta">${escapeHtml(note.timestamp)} · ${escapeHtml(note.audience.replace("_", " "))}${note.local ? " · local demo" : " · synthetic fixture"}</p></div><button class="bookmark" type="button" aria-label="Bookmark locally">☆</button></header><p class="post-body">${escapeHtml(note.body)}</p>${media}<div class="post-actions"><button type="button" data-action="react" data-note="${escapeHtml(note.id)}" aria-pressed="${reacted}">♡ ${note.reactions + (reacted ? 1 : 0)}</button><span>Comments ${note.comments}</span><span>Reposts ${note.reposts}</span><span>Local UI only</span></div>${renderReplies(note, common, people)}</article>`;
  }).join("");
}

export function renderHome(common, reactionState) {
  return `<div class="home-heading"><div><p class="eyebrow">HODLXXI Social</p><h1>Home</h1></div><span class="local-pill">Offline demo</span></div>${renderComposer(common)}<section class="feed-stack" aria-label="Local synthetic feed">${renderFeed(common, reactionState)}</section>`;
}

export function renderContextSummary({ viewer, viewerStatus, participants, statuses, edges, notes }) {
  if (!validViewer({ viewer, viewerStatus, participants, statuses })) return '<article class="viewer-card restricted"><strong>Local context unavailable</strong></article>';
  const contexts = participants.map((person) => relationshipContext(viewer.id, person.id, edges));
  const direct = contexts.filter((context) => context === RelationshipContext.DIRECT).length;
  const reach = contexts.filter((context) => context === RelationshipContext.FRIEND_OF_FRIEND).length;
  const trust = edges.filter((edge) => edge.type === EdgeType.SPONSOR_TRUST && (edge.from === viewer.id || edge.to === viewer.id)).length;
  return `<article class="viewer-card context-summary"><p class="eyebrow">Local context</p><strong>${viewerStatus} · externally derived</strong><dl><div><dt>Direct friends</dt><dd>${direct}</dd></div><div><dt>Friend-of-friend reach</dt><dd>${reach}</dd></div><div><dt>Sponsor-trust records</dt><dd>${trust}</dd></div><div><dt>Synthetic fixture posts</dt><dd>${notes.length}</dd></div></dl><p class="notice">Fixture summary only. Not live network activity or a trust score.</p></article>`;
}
