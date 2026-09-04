const SAFE_ALIAS = /^[A-Za-z0-9._~-]{1,128}$/;
const UNSAFE_ALIAS = /^(?:[0-9a-f]{64}|npub1|nprofile1|nsec1|xpub|tpub|ypub|zpub|vpub|xprv|tprv|yprv|zprv|vprv|bc1|tb1)/i;
const DEVICE_STATES = new Set(["ready", "not-configured", "unavailable"]);
const DIRECTIONS = new Set(["incoming", "outgoing"]);
const MESSAGE_STATES = new Set(["sent", "delivered", "opened"]);

const plainObject = (value) =>
  Boolean(value) &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const exactKeys = (value, expected) => {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length &&
    wanted.every((name, index) => name === actual[index]);
};

const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

const safeText = (value, maximum) =>
  typeof value === "string" &&
  value.length > 0 &&
  [...value].length <= maximum &&
  !/[\u0000-\u001f\u007f]/u.test(value) &&
  value.trim() === value;

const safeAlias = (value) =>
  typeof value === "string" &&
  SAFE_ALIAS.test(value) &&
  !UNSAFE_ALIAS.test(value) &&
  !value.includes("@") &&
  !/^\d{7,15}$/.test(value);

const normalizePerson = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["alias", "label", "status"]) ||
    !safeAlias(value.alias) ||
    !(value.label === null || safeText(value.label, 64)) ||
    value.status !== "full"
  ) {
    throw new TypeError("invalid secure messaging preview person");
  }
  return Object.freeze({ ...value });
};

const normalizeMessage = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["body", "direction", "state", "time"]) ||
    !safeText(value.body, 2_000) ||
    !DIRECTIONS.has(value.direction) ||
    !MESSAGE_STATES.has(value.state) ||
    !safeText(value.time, 32)
  ) {
    throw new TypeError("invalid secure messaging preview message");
  }
  return Object.freeze({ ...value });
};

const normalizeConversation = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["id", "messages", "person", "timestamp", "unread"]) ||
    !safeText(value.id, 64) ||
    !Array.isArray(value.messages) ||
    value.messages.length > 50 ||
    !safeText(value.timestamp, 32) ||
    !Number.isSafeInteger(value.unread) ||
    value.unread < 0 ||
    value.unread > 999
  ) {
    throw new TypeError("invalid secure messaging preview conversation");
  }
  return Object.freeze({
    id: value.id,
    person: normalizePerson(value.person),
    timestamp: value.timestamp,
    unread: value.unread,
    messages: Object.freeze(value.messages.map(normalizeMessage))
  });
};

export function normalizeSecureMessagingPreview(value) {
  if (
    !plainObject(value) ||
    !exactKeys(value, [
      "conversations",
      "device",
      "recipientCandidates",
      "selectedConversationId"
    ]) ||
    !Array.isArray(value.conversations) ||
    value.conversations.length > 32 ||
    !Array.isArray(value.recipientCandidates) ||
    value.recipientCandidates.length > 32 ||
    !(value.selectedConversationId === null || safeText(value.selectedConversationId, 64)) ||
    !plainObject(value.device) ||
    !exactKeys(value.device, ["label", "state"]) ||
    !safeText(value.device.label, 64) ||
    !DEVICE_STATES.has(value.device.state)
  ) {
    throw new TypeError("invalid secure messaging preview model");
  }

  const conversations = value.conversations.map(normalizeConversation);
  const ids = new Set();
  for (const item of conversations) {
    if (ids.has(item.id)) throw new TypeError("duplicate conversation");
    ids.add(item.id);
  }

  if (
    value.selectedConversationId !== null &&
    !ids.has(value.selectedConversationId)
  ) {
    throw new TypeError("unknown selected conversation");
  }

  const recipients = value.recipientCandidates.map(normalizePerson);
  const aliases = new Set();
  for (const person of recipients) {
    if (aliases.has(person.alias)) throw new TypeError("duplicate recipient alias");
    aliases.add(person.alias);
  }

  return Object.freeze({
    conversations: Object.freeze(conversations),
    selectedConversationId: value.selectedConversationId,
    recipientCandidates: Object.freeze(recipients),
    device: Object.freeze({ ...value.device })
  });
}

const displayName = (person) => person.label ?? person.alias;
const initial = (person) => [...displayName(person)][0]?.toUpperCase() ?? "H";

const renderDeviceStatus = (device) => {
  if (device.state === "ready") {
    return `<div class="secure-device secure-device-ready">` +
      `<span class="secure-device-icon" aria-hidden="true">✓</span>` +
      `<div><strong>Secure Messages ready</strong>` +
      `<p>${escapeHtml(device.label)} · private encryption key stays on this device</p></div>` +
      `<button type="button" data-preview-action="manage-device">Manage</button></div>`;
  }
  if (device.state === "not-configured") {
    return `<div class="secure-device secure-device-setup">` +
      `<span class="secure-device-icon" aria-hidden="true">◇</span>` +
      `<div><strong>Set up Secure Messages</strong>` +
      `<p>Create a separate device encryption key. No Nostr extension is required for internal messages.</p></div>` +
      `<button type="button" data-preview-action="setup-device">Set up</button></div>`;
  }
  return `<div class="secure-device secure-device-unavailable">` +
    `<span class="secure-device-icon" aria-hidden="true">!</span>` +
    `<div><strong>Secure Messages unavailable</strong>` +
    `<p>This device cannot establish a safe encryption state.</p></div></div>`;
};

const renderConversationRow = (conversation, selected) => {
  const person = conversation.person;
  const last = conversation.messages.at(-1)?.body ?? "No messages";
  return `<button class="secure-conversation-row${selected ? " selected" : ""}" type="button" data-conversation-id="${escapeHtml(conversation.id)}"${selected ? ' aria-current="true"' : ""}>` +
    `<span class="secure-avatar" aria-hidden="true">${escapeHtml(initial(person))}</span>` +
    `<span class="secure-conversation-copy"><span class="secure-conversation-name">${escapeHtml(displayName(person))}</span>` +
    `<span class="secure-conversation-preview">${escapeHtml(last)}</span></span>` +
    `<span class="secure-conversation-meta"><time>${escapeHtml(conversation.timestamp)}</time>` +
    `${conversation.unread ? `<span class="secure-unread">${conversation.unread}</span>` : ""}</span></button>`;
};

const renderTranscript = (conversation) => conversation.messages.map((message) =>
  `<article class="secure-message ${message.direction === "outgoing" ? "mine" : "theirs"}">` +
  `<p>${escapeHtml(message.body)}</p>` +
  `<footer><time>${escapeHtml(message.time)}</time>` +
  `${message.direction === "outgoing" ? `<span>${escapeHtml(message.state)}</span>` : ""}</footer></article>`
).join("");

const renderConversation = (conversation) => {
  if (!conversation) {
    return `<section class="secure-empty-detail"><div class="secure-empty-mark" aria-hidden="true">✦</div>` +
      `<h2>Select a conversation</h2>` +
      `<p>Your encrypted conversations will appear here. This preview does not send, encrypt, or store anything.</p></section>`;
  }
  const person = conversation.person;
  return `<section class="secure-thread">` +
    `<header class="secure-thread-header"><div class="secure-person"><span class="secure-avatar" aria-hidden="true">${escapeHtml(initial(person))}</span>` +
    `<div><h2>${escapeHtml(displayName(person))}</h2><p>Current Full member · viewer-private identity</p></div></div>` +
    `<span class="secure-lock-pill">⌁ End-to-end encrypted</span></header>` +
    `<div class="secure-thread-notice"><span aria-hidden="true">i</span>` +
    `<p>When connected, HODLXXI will store ciphertext only. Private device keys and plaintext stay on user devices.</p></div>` +
    `<div class="secure-transcript" aria-label="Preview transcript">${renderTranscript(conversation)}</div>` +
    `<form class="secure-composer" data-preview-form="message">` +
    `<label class="sr-only" for="secure-preview-message">Message</label>` +
    `<textarea id="secure-preview-message" maxlength="2000" placeholder="Write a message…"></textarea>` +
    `<button type="submit" aria-label="Send preview message">↑</button>` +
    `<div class="secure-composer-meta"><span>🔒 Encrypted on your device</span><span>Preview only · Send disabled by design</span></div>` +
    `</form></section>`;
};

const renderRecipientCard = (person) =>
  `<button class="secure-recipient-card" type="button" data-preview-action="select-recipient" data-recipient-alias="${escapeHtml(person.alias)}">` +
  `<span class="secure-avatar" aria-hidden="true">${escapeHtml(initial(person))}</span>` +
  `<span><strong>${escapeHtml(displayName(person))}</strong>` +
  `<small>Current Full · ${escapeHtml(person.alias)}</small></span>` +
  `<span aria-hidden="true">›</span></button>`;

export function renderSecureMessagingPreview(input) {
  const model = normalizeSecureMessagingPreview(input);
  const selected = model.conversations.find(
    (item) => item.id === model.selectedConversationId
  ) ?? null;

  return `<main class="secure-preview">` +
    `<div class="secure-preview-banner"><strong>V1.28 UX preview</strong>` +
    `<span>No network · no crypto · no persistence · no production wiring</span></div>` +
    `<header class="secure-preview-header"><div><p class="secure-eyebrow">HODLXXI Social</p>` +
    `<h1>Messages</h1><p>Private conversations for current Full members.</p></div>` +
    `<button class="secure-primary" type="button" data-preview-action="new-message">+ New message</button></header>` +
    `${renderDeviceStatus(model.device)}` +
    `<section class="secure-message-layout">` +
    `<aside class="secure-conversation-list"><div class="secure-list-heading"><strong>Conversations</strong>` +
    `<span>${model.conversations.length}</span></div>` +
    `<label class="secure-search"><span aria-hidden="true">⌕</span><input type="search" placeholder="Search your labels" aria-label="Search conversations"></label>` +
    `<div class="secure-conversation-stack">${model.conversations.map((item) => renderConversationRow(item, item.id === model.selectedConversationId)).join("") || `<div class="secure-list-empty"><strong>No conversations</strong><p>Start with a current Full Network member.</p></div>`}</div>` +
    `<div class="secure-list-footer"><span aria-hidden="true">◉</span><p>Recipient identity stays behind viewer-private aliases and short-lived capabilities.</p></div></aside>` +
    `<div class="secure-thread-panel">${renderConversation(selected)}</div></section>` +
    `<section class="secure-new-message"><div class="secure-new-message-heading"><div><p class="secure-eyebrow">New message preview</p>` +
    `<h2>Select a Full Network member</h2><p>Private labels are shown when this device has one. Raw participant keys are not shown.</p></div>` +
    `<span class="secure-step-pill">V1.27 → rc_… → V1.28 crypto package</span></div>` +
    `<div class="secure-recipient-grid">${model.recipientCandidates.map(renderRecipientCard).join("")}</div></section>` +
    `<section class="secure-privacy-grid">` +
    `<article><span>01</span><strong>Encrypt locally</strong><p>Plaintext never becomes server transport.</p></article>` +
    `<article><span>02</span><strong>Ciphertext storage</strong><p>HODLXXI routes and retains encrypted objects only.</p></article>` +
    `<article><span>03</span><strong>Device-local decrypt</strong><p>Mobile and desktop use dedicated Social device keys.</p></article>` +
    `<article><span>04</span><strong>Nostr optional</strong><p>Internal messages do not require external relays or NIP-07.</p></article>` +
    `</section></main>`;
}
