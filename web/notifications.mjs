import { relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { conversationAccess } from "./messages.mjs";
import { groupAccess } from "./groups.mjs";
import { renderEmptyState, renderRestrictedState } from "./components.mjs";

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const peopleById = (participants) => new Map(participants.map((person) => [person.id, person]));

export function initializeNotificationState(items = []) {
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

export function deriveNotifications(input, state = initializeNotificationState(input.notifications ?? [])) {
  return Object.freeze((input.notifications ?? []).map((item) => {
    const access = actorAccess(item, input);
    if (!access.visible) return Object.freeze({ restricted: true });
    return Object.freeze({ ...item, actor: access.actor, unread: Boolean(state[item.id]), route: safeNotificationRoute(item, input) });
  }));
}

export function visibleUnreadCount(input, state = initializeNotificationState(input.notifications ?? [])) {
  return deriveNotifications(input, state).filter((item) => !item.restricted && item.unread).length;
}

export function renderNotifications(input, state = initializeNotificationState(input.notifications ?? [])) {
  const items = deriveNotifications(input, state).map((item) => {
    if (item.restricted) return renderRestrictedState("notification");
    const target = item.route ? `<a class="notification-target" href="${escapeHtml(item.route)}">${escapeHtml(item.targetLabel)}</a>` : `<span class="notification-target disabled">Target unavailable</span>`;
    const control = item.unread ? `<button type="button" data-action="mark-notification-read" data-notification="${escapeHtml(item.id)}">Mark read</button>` : `<span class="read-label">Read</span>`;
    return `<article class="notification-row${item.unread ? " unread" : ""}"><span class="avatar" aria-hidden="true">${escapeHtml(item.actor.displayName[0])}</span><div class="notification-copy"><strong>${escapeHtml(item.actor.displayName)}</strong><p>${escapeHtml(item.action)} · ${target}</p><time>${escapeHtml(item.timestamp)} · synthetic local</time></div>${control}</article>`;
  }).join("");
  return `<section class="notifications-product"><div class="local-disclosure"><strong>Local demo notifications</strong><span>Synthetic activity only — not live network telemetry. Read state resets on reload.</span></div><div class="notification-toolbar"><span>${visibleUnreadCount(input, state)} unread locally</span><button type="button" data-action="mark-all-notifications-read">Mark all read</button></div><div class="notification-list">${items || renderEmptyState("notifications")}</div><p class="notice">Friendship, reactions, messaging, and groups do not prove covenant trust or grant Full or Operator status. CRT truth remains externally derived and read-only.</p></section>`;
}
