import { relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { renderEmptyState, renderRestrictedState } from "./components.mjs";

const freezeMessages = (items) => Object.freeze(items.map((item) => Object.freeze({ ...item })));
export const conversations = Object.freeze([
  Object.freeze({ id: "chat-01", memberIds: Object.freeze(["a".repeat(64), "b".repeat(64)]), unreadFor: Object.freeze(["a".repeat(64)]), messages: freezeMessages([
    { authorId: "b".repeat(64), body: "The local product shell is taking shape.", timestamp: "Today · 09:42" },
    { authorId: "a".repeat(64), body: "Good. Messaging and covenant trust stay separate.", timestamp: "Today · 09:45" }
  ]) }),
  Object.freeze({ id: "chat-02", memberIds: Object.freeze(["a".repeat(64), "c".repeat(64)]), unreadFor: Object.freeze([]), messages: freezeMessages([
    { authorId: "c".repeat(64), body: "Visibility still follows the current viewer policy.", timestamp: "Yesterday · 16:18" }
  ]) })
]);

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const byId = (participants) => new Map(participants.map((person) => [person.id, person]));
const restricted = () => renderRestrictedState("conversation");

export function conversationAccess({ conversationId, viewer, viewerStatus, participants, edges, items = conversations }) {
  const conversation = items.find((item) => item.id === conversationId);
  if (!conversation || !viewer || !conversation.memberIds.includes(viewer.id)) return Object.freeze({ visible: false, reason: "restricted" });
  const people = byId(participants);
  const members = conversation.memberIds.map((id) => people.get(id));
  if (members.some((person) => !person)) return Object.freeze({ visible: false, reason: "restricted" });
  const visible = members.every((person) => visibilityDecision({ viewerStatus, context: relationshipContext(viewer.id, person.id, edges), policy: "social" }).visible);
  return visible ? Object.freeze({ visible: true, conversation, members: Object.freeze(members) }) : Object.freeze({ visible: false, reason: "restricted" });
}

export function visibleConversations(input) {
  return Object.freeze((input.items ?? conversations).map((conversation) => conversationAccess({ ...input, conversationId: conversation.id })).filter((result) => result.visible));
}

export function initializeLocalMessages(items = conversations) {
  return Object.freeze(Object.fromEntries(items.map((conversation) => [conversation.id, freezeMessages(conversation.messages)])));
}

export function appendLocalMessage(state, { conversationId, viewer, viewerStatus, participants, edges, body, timestamp = "Now · local" }, items = conversations) {
  const access = conversationAccess({ conversationId, viewer, viewerStatus, participants, edges, items });
  const text = typeof body === "string" ? body.trim() : "";
  if (!access.visible || !text || text.length > 500) return state;
  const current = Array.isArray(state?.[conversationId]) ? state[conversationId] : access.conversation.messages;
  return Object.freeze({ ...state, [conversationId]: freezeMessages([...current, { authorId: viewer.id, body: text, timestamp, local: true }]) });
}

function conversationName(access, viewer) {
  return access.members.find((person) => person.id !== viewer.id)?.displayName ?? "Your local notes";
}

function renderList(input, selectedId) {
  const available = visibleConversations(input);
  if (!available.length) return renderEmptyState("conversations");
  return available.map((access) => {
    const unread = access.conversation.unreadFor.includes(input.viewer.id);
    const name = conversationName(access, input.viewer);
    return `<a class="conversation-row${selectedId === access.conversation.id ? " selected" : ""}${unread ? " unread" : ""}" href="#/messages/${access.conversation.id}"${selectedId === access.conversation.id ? ' aria-current="page"' : ""}><span class="avatar" aria-hidden="true">${escapeHtml(name[0])}</span><span><strong>${escapeHtml(name)}</strong><small>${unread ? "Unread local demo" : "Read local demo"}</small></span><time>${escapeHtml(access.conversation.messages.at(-1)?.timestamp ?? "Local")}</time></a>`;
  }).join("");
}

function renderTranscript(access, viewer, state) {
  const people = byId(access.members);
  const messages = state?.[access.conversation.id] ?? access.conversation.messages;
  return messages.map((message) => {
    const author = people.get(message.authorId);
    if (!author) return "";
    const mine = author.id === viewer.id;
    return `<article class="message-bubble${mine ? " mine" : ""}"><strong>${mine ? "You" : escapeHtml(author.displayName)}</strong><p>${escapeHtml(message.body)}</p><time>${escapeHtml(message.timestamp)}${message.local ? " · in memory" : ""}</time></article>`;
  }).join("");
}

export function renderMessages(input, selectedId, state = initializeLocalMessages(input.items ?? conversations)) {
  const list = renderList(input, selectedId);
  let detail = renderEmptyState("conversation-selection");
  if (selectedId) {
    const access = conversationAccess({ ...input, conversationId: selectedId });
    if (!access.visible) detail = restricted();
    else {
      const name = conversationName(access, input.viewer);
      const other = access.members.find((person) => person.id !== input.viewer.id);
      const heading = other ? `<a class="person-link" href="#/profile/${other.id}">${escapeHtml(name)}</a>` : escapeHtml(name);
      detail = `<section class="conversation-detail"><header><p class="eyebrow">Selected conversation</p><h2>${heading}</h2><p class="meta">Current viewer: ${escapeHtml(input.viewer.displayName)}</p></header><div class="message-transcript">${renderTranscript(access, input.viewer, state)}</div><form id="message-composer" class="message-composer"><label for="message-body">Local demo message</label><textarea id="message-body" name="body" maxlength="500" required placeholder="Write an in-memory demo message"></textarea><input type="hidden" name="conversation" value="${access.conversation.id}"><button type="submit">Add locally</button></form></section>`;
    }
  }
  return `<section class="messages-product"><div class="local-disclosure"><strong>Local demo messaging</strong><span>Messages are not transported and not encrypted. Nothing is delivered or persisted.</span></div><div class="split-surface"><aside class="surface-list" aria-label="Accessible local conversations">${list}</aside><div class="surface-detail">${detail}</div></div><p class="notice">Messaging activity is not trust or status and does not grant authentication or protocol authority.</p></section>`;
}
