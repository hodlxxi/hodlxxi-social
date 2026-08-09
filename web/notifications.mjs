import { relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { conversationAccess } from "./messages.mjs";
import { groupAccess } from "./groups.mjs";
import { renderEmptyState, renderRestrictedState } from "./components.mjs";

const freezeItems = (items) => Object.freeze(items.map((item) => Object.freeze({ ...item, target: Object.freeze({ ...item.target }) })));

export const notifications = freezeItems([
  { id: "local-notice-friend", actorId: "a".repeat(64), kind: "friend", action: "shared profile and social connection activity", targetLabel: "Profile", timestamp: "Today · 10:08", unread: true, target: { type: "profile", id: "a".repeat(64) } },
  { id: "local-notice-reaction", actorId: "b".repeat(64), kind: "reaction", action: "reacted to a synthetic local post", targetLabel: "Home", timestamp: "Today · 09:54", unread: true, target: { type: "home" } },
  { id: "local-notice-reply", actorId: "c".repeat(64), kind: "reply", action: "replied to a demo post", targetLabel: "Home", timestamp: "Yesterday · 16:22", unread: false, target: { type: "home" } },
  { id: "local-notice-message", actorId: "a".repeat(64), kind: "message", action: "added a new local demo message", targetLabel: "Messages", timestamp: "Yesterday · 14:06", unread: true, target: { type: "message", id: "chat-01" } },
  { id: "local-notice-group", actorId: "b".repeat(64), kind: "group", action: "added synthetic local group activity", targetLabel: "Local Builders", timestamp: "Friday · 11:18", unread: false, target: { type: "group", id: "group-01" } }
]);

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const peopleById = (participants) => new Map(participants.map((person) => [person.id, person]));

export function initializeNotificationState(items = notifications) {
  return Object.freeze(Object.fromEntries(items.map((item) => [item.id, Boolean(item.unread)])));
}

export function unreadCount(state = Object.freeze({})) {
  return Object.values(state).filter(Boolean).length;
}

export function markNotificationRead(state, notificationId) {
  if (!Object.hasOwn(state ?? {}, notificationId) || state[notificationId] === false) return state;
  return Object.freeze({ ...state, [notificationId]: false });
}

export function markAllNotificationsRead(state = Object.freeze({})) {
  return Object.freeze(Object.fromEntries(Object.keys(state).map((id) => [id, false])));
}

function actorAccess(item, input) {
  const actor = peopleById(input.participants).get(item.actorId);
  if (!actor || !input.viewer) return Object.freeze({ visible: false });
  const context = relationshipContext(input.viewer.id, actor.id, input.edges);
  const visible = visibilityDecision({ viewerStatus: input.viewerStatus, context, policy: "social" }).visible;
  return visible ? Object.freeze({ visible: true, actor }) : Object.freeze({ visible: false });
}

export function safeNotificationRoute(item, input) {
  if (!actorAccess(item, input).visible) return undefined;
  if (item.target.type === "home") return "#/home";
  if (item.target.type === "profile") {
    const actor = peopleById(input.participants).get(item.target.id);
    if (!actor) return undefined;
    const context = relationshipContext(input.viewer.id, actor.id, input.edges);
    return visibilityDecision({ viewerStatus: input.viewerStatus, context, policy: "social" }).visible ? `#/profile/${actor.id}` : undefined;
  }
  if (item.target.type === "message") {
    return conversationAccess({ ...input, conversationId: item.target.id }).visible ? `#/messages/${item.target.id}` : undefined;
  }
  if (item.target.type === "group") {
    return groupAccess({ ...input, groupId: item.target.id }).visible ? `#/groups/${item.target.id}` : undefined;
  }
  return undefined;
}

export function deriveNotifications(input, state = initializeNotificationState(input.items ?? notifications)) {
  return Object.freeze((input.items ?? notifications).map((item) => {
    const access = actorAccess(item, input);
    if (!access.visible) return Object.freeze({ restricted: true });
    return Object.freeze({ ...item, actor: access.actor, unread: Boolean(state[item.id]), route: safeNotificationRoute(item, input) });
  }));
}

export function visibleUnreadCount(input, state = initializeNotificationState(input.items ?? notifications)) {
  return deriveNotifications(input, state).filter((item) => !item.restricted && item.unread).length;
}

export function renderNotifications(input, state = initializeNotificationState(input.items ?? notifications)) {
  const items = deriveNotifications(input, state).map((item) => {
    if (item.restricted) return renderRestrictedState("notification");
    const target = item.route ? `<a class="notification-target" href="${escapeHtml(item.route)}">${escapeHtml(item.targetLabel)}</a>` : `<span class="notification-target disabled">Target unavailable</span>`;
    const control = item.unread ? `<button type="button" data-action="mark-notification-read" data-notification="${escapeHtml(item.id)}">Mark read</button>` : `<span class="read-label">Read</span>`;
    return `<article class="notification-row${item.unread ? " unread" : ""}"><span class="avatar" aria-hidden="true">${escapeHtml(item.actor.displayName[0])}</span><div class="notification-copy"><strong>${escapeHtml(item.actor.displayName)}</strong><p>${escapeHtml(item.action)} · ${target}</p><time>${escapeHtml(item.timestamp)} · synthetic local</time></div>${control}</article>`;
  }).join("");
  return `<section class="notifications-product"><div class="local-disclosure"><strong>Local demo notifications</strong><span>Synthetic activity only — not live network telemetry. Read state resets on reload.</span></div><div class="notification-toolbar"><span>${visibleUnreadCount(input, state)} unread locally</span><button type="button" data-action="mark-all-notifications-read">Mark all read</button></div><div class="notification-list">${items || renderEmptyState("notifications")}</div><p class="notice">Friendship, reactions, messaging, and groups do not prove covenant trust or grant Full or Operator status. CRT truth remains externally derived and read-only.</p></section>`;
}
