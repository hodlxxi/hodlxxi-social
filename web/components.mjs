export const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

const validStatuses = new Set(["limited", "full", "operator"]);

export function renderStatusBadge(status) {
  const safeStatus = validStatuses.has(status) ? status : "limited";
  return `<span class="badge badge-${safeStatus}" title="Externally derived access status; not legal identity">${safeStatus}</span>`;
}

function renderState(kind, title, detail) {
  return `<article class="ui-state ui-state-${kind}"><div><strong>${escapeHtml(title)}</strong><p class="meta">${escapeHtml(detail)}</p></div></article>`;
}

const restrictedStates = Object.freeze({
  generic: Object.freeze(["Restricted", "This content is unavailable under the social visibility policy."]),
  profile: Object.freeze(["Profile restricted", "This participant profile is unavailable under the social visibility policy."]),
  discovery: Object.freeze(["Restricted connection", "Friend-of-friend discovery is unavailable for this access level."]),
  connections: Object.freeze(["Connections restricted", "Direct connection details are unavailable."]),
  trust: Object.freeze(["Trust records restricted", "Sponsor-trust details are unavailable."]),
  "trust-record": Object.freeze(["Trust record restricted", "An associated sponsor-trust record exists, but its participant identity is not visible under social policy."]),
  circle: Object.freeze(["Circle unavailable", "A valid synthetic viewer and access assertion are required."]),
  conversation: Object.freeze(["Conversation restricted", "This local conversation is unavailable under the social visibility policy."]),
  group: Object.freeze(["Group restricted", "This local group is unavailable for the current viewer."]),
  notification: Object.freeze(["Restricted network activity", "Identity and target are unavailable under the social visibility policy."])
});

const emptyStates = Object.freeze({
  generic: Object.freeze(["Nothing to show", "No permitted local content is available."]),
  connections: Object.freeze(["No direct connections", "No direct friends are available under the social visibility policy."]),
  "friend-discovery": Object.freeze(["No discoverable connections", "No friend-of-friend participants are available under the social visibility policy."]),
  trust: Object.freeze(["No associated trust records", "Sponsor-trust is external provenance, not a friend connection."]),
  feed: Object.freeze(["No visible local posts", "The local audience and social visibility policies fail closed."]),
  conversations: Object.freeze(["No conversations", "No local conversations are available for this viewer."]),
  "conversation-selection": Object.freeze(["Choose a conversation", "Select an accessible synthetic conversation from the local list."]),
  groups: Object.freeze(["No local groups", "No local groups are available for this viewer."]),
  "group-selection": Object.freeze(["Choose a group", "Select an accessible synthetic group from the local list."]),
  search: Object.freeze(["Search this local demo", "Find permitted participants, visible posts, and accessible synthetic groups. Search history is not stored."]),
  "search-results": Object.freeze(["No local results", "No permitted content matched this query."]),
  discovery: Object.freeze(["No permitted local suggestions", "No permitted local suggestions are available in this category."]),
  activity: Object.freeze(["Activity unavailable", "No viewer-scoped local summary is available."]),
  notifications: Object.freeze(["No notifications", "No permitted local notifications are available."])
});

const unavailableStates = Object.freeze({
  route: Object.freeze(["Route not found", "Use the application navigation to choose a local surface."]),
  search: Object.freeze(["Search query unavailable", "That local URL query could not be read safely. Try a plain, non-secret search."])
});

const safeState = (states, key) => states[key] ?? states.generic ?? Object.values(states)[0];

// Closed keys ensure denied identity data can never become presentation copy.
export const renderRestrictedState = (key = "generic") => renderState("restricted", ...safeState(restrictedStates, key));
export const renderEmptyState = (key = "generic") => renderState("empty", ...safeState(emptyStates, key));
export const renderUnavailableState = (key = "route") => renderState("unavailable", ...safeState(unavailableStates, key));

export function renderPageFrame({ eyebrow = "HODLXXI Social", title, content, className = "" }) {
  return `<section class="page${className ? ` ${escapeHtml(className)}` : ""}"><header class="page-header"><p class="eyebrow">${escapeHtml(eyebrow)}</p><h1>${escapeHtml(title)}</h1></header><div class="page-body">${content}</div></section>`;
}
