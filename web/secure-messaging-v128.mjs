import {
  createBrowserPrivateLabelStore
} from "./private-label-store.mjs?v=1.28.1";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const SAFE_ALIAS = /^[A-Za-z0-9._~-]{1,128}$/;
const UNSAFE_ALIAS = /^(?:[0-9a-f]{64}|npub1|nprofile1|nsec1|xpub|tpub|ypub|zpub|vpub|xprv|tprv|yprv|zprv|vprv|bc1|tb1)/i;
const BITCOIN_BASE58_ADDRESS = /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const MAX_SESSION_BODY_BYTES = 1024;
const MAX_DIRECTORY_BODY_BYTES = 1024 * 1024;

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

const safeAlias = (value) =>
  typeof value === "string" &&
  SAFE_ALIAS.test(value) &&
  !UNSAFE_ALIAS.test(value) &&
  !BITCOIN_BASE58_ADDRESS.test(value) &&
  !/^\d{7,15}$/.test(value) &&
  !value.includes("@");

const aliasSummary = (alias) =>
  alias.length <= 24
    ? alias
    : `${alias.slice(0, 11)}...${alias.slice(-8)}`;

const displayName = (recipient) =>
  recipient.label ?? aliasSummary(recipient.alias);

const initial = (recipient) => {
  const value = displayName(recipient);
  const character = [...value].find((item) => /[A-Za-z0-9]/.test(item));
  return character?.toUpperCase() ?? "H";
};

async function decodeJsonResponse(response, maximumBodyBytes) {
  if (
    !response ||
    response.status !== 200 ||
    typeof response.text !== "function" ||
    typeof response.headers?.get !== "function"
  ) {
    throw new TypeError("secure messaging read unavailable");
  }

  const contentType = response.headers.get("content-type");
  if (
    typeof contentType !== "string" ||
    contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json"
  ) {
    throw new TypeError("secure messaging read unavailable");
  }

  const body = await response.text();
  if (
    body.length === 0 ||
    new TextEncoder().encode(body).byteLength > maximumBodyBytes
  ) {
    throw new TypeError("secure messaging read unavailable");
  }

  try {
    return JSON.parse(body);
  } catch {
    throw new TypeError("secure messaging read unavailable");
  }
}

export function parseSecureMessagingSessionDocument(value) {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["authenticated", "subject"]) ||
    value.authenticated !== true ||
    typeof value.subject !== "string" ||
    !CANONICAL_SUBJECT.test(value.subject)
  ) {
    throw new TypeError("invalid secure messaging session");
  }

  return Object.freeze({
    authenticated: true,
    subject: value.subject
  });
}

export function parseSecureMessagingDirectoryDocument(value) {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["participants", "state"]) ||
    value.state !== "available" ||
    !Array.isArray(value.participants) ||
    value.participants.length > 4096
  ) {
    throw new TypeError("invalid secure messaging directory");
  }

  const aliases = new Set();
  const participants = [];

  for (const participant of value.participants) {
    if (
      !plainObject(participant) ||
      !exactKeys(participant, ["alias"]) ||
      !safeAlias(participant.alias) ||
      aliases.has(participant.alias)
    ) {
      throw new TypeError("invalid secure messaging directory");
    }

    aliases.add(participant.alias);
    participants.push(Object.freeze({ alias: participant.alias }));
  }

  return Object.freeze({
    state: "available",
    participants: Object.freeze(participants)
  });
}

export async function readSecureMessagingSession(fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("secure messaging session unavailable");
  }

  const response = await fetchImpl("/auth/session", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: { Accept: "application/json" }
  });

  return parseSecureMessagingSessionDocument(
    await decodeJsonResponse(response, MAX_SESSION_BODY_BYTES)
  );
}

export async function readSecureMessagingFullDirectory(
  fetchImpl = globalThis.fetch
) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("secure messaging directory unavailable");
  }

  const response = await fetchImpl("/auth/full-directory", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: { Accept: "application/json" }
  });

  return parseSecureMessagingDirectoryDocument(
    await decodeJsonResponse(response, MAX_DIRECTORY_BODY_BYTES)
  );
}

export function buildSecureMessagingRecipients({
  subject,
  directory,
  labelStore
}) {
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject) ||
    !directory ||
    directory.state !== "available" ||
    !Array.isArray(directory.participants) ||
    !labelStore ||
    typeof labelStore.read !== "function"
  ) {
    throw new TypeError("invalid secure messaging recipient context");
  }

  return Object.freeze(directory.participants.map((participant) => {
    let label = null;

    try {
      const candidate = labelStore.read({
        subject,
        alias: participant.alias
      });
      if (typeof candidate === "string" && candidate.length > 0) {
        label = candidate;
      }
    } catch {
      label = null;
    }

    return Object.freeze({
      alias: participant.alias,
      label
    });
  }));
}

export async function loadSecureMessagingSnapshot({
  access,
  fetchImpl = globalThis.fetch,
  labelStore
} = {}) {
  if (access !== "full") {
    return Object.freeze({
      state: "restricted",
      recipients: Object.freeze([])
    });
  }

  try {
    const session = await readSecureMessagingSession(fetchImpl);
    const directory = await readSecureMessagingFullDirectory(fetchImpl);
    const recipients = buildSecureMessagingRecipients({
      subject: session.subject,
      directory,
      labelStore
    });

    return Object.freeze({
      state: "available",
      recipients
    });
  } catch {
    return Object.freeze({
      state: "unavailable",
      recipients: Object.freeze([])
    });
  }
}

const renderRecipientCard = (recipient, selected) =>
  `<button class="secure-v128-recipient${selected ? " selected" : ""}" type="button" data-secure-v128-recipient="${escapeHtml(recipient.alias)}"${selected ? ' aria-current="true"' : ""}>` +
  `<span class="secure-v128-avatar" aria-hidden="true">${escapeHtml(initial(recipient))}</span>` +
  `<span class="secure-v128-recipient-copy">` +
  `<strong>${escapeHtml(displayName(recipient))}</strong>` +
  `<small>Current Full member</small>` +
  `<code title="${escapeHtml(recipient.alias)}">${escapeHtml(aliasSummary(recipient.alias))}</code>` +
  `</span><span class="secure-v128-chevron" aria-hidden="true">&rsaquo;</span></button>`;

const renderRecipientPicker = (snapshot, selectedAlias, filter) => {
  if (snapshot.state === "restricted") {
    return `<div class="secure-v128-state secure-v128-state-restricted">` +
      `<span class="secure-v128-state-icon" aria-hidden="true">!</span>` +
      `<div><strong>Full access required</strong>` +
      `<p>V1.28 direct messaging begins with current Full-to-Full recipient selection. No private directory request is made for Limited access.</p></div></div>`;
  }

  if (snapshot.state === "unavailable") {
    return `<div class="secure-v128-state">` +
      `<span class="secure-v128-state-icon" aria-hidden="true">!</span>` +
      `<div><strong>Private recipient directory unavailable</strong>` +
      `<p>No recipient aliases are displayed when the authenticated Full Directory cannot be accepted.</p></div></div>`;
  }

  const normalizedFilter = filter.trim().toLowerCase();
  const recipients = snapshot.recipients.filter((recipient) => {
    if (!normalizedFilter) return true;
    return [recipient.label, recipient.alias]
      .filter(Boolean)
      .some((value) => value.toLowerCase().includes(normalizedFilter));
  });

  if (snapshot.recipients.length === 0) {
    return `<div class="secure-v128-state">` +
      `<span class="secure-v128-state-icon" aria-hidden="true">0</span>` +
      `<div><strong>No other Full members are visible</strong>` +
      `<p>The current viewer-private Full Directory contains no recipient aliases.</p></div></div>`;
  }

  if (recipients.length === 0) {
    return `<div class="secure-v128-state"><span class="secure-v128-state-icon" aria-hidden="true">0</span>` +
      `<div><strong>No matching private labels</strong><p>Try another device-local label or viewer-private alias.</p></div></div>`;
  }

  return recipients.map((recipient) =>
    renderRecipientCard(recipient, recipient.alias === selectedAlias)
  ).join("");
};

const renderThread = (snapshot, selectedAlias) => {
  const recipient = snapshot.state === "available"
    ? snapshot.recipients.find((item) => item.alias === selectedAlias) ?? null
    : null;

  if (!recipient) {
    return `<section class="secure-v128-empty-thread">` +
      `<div class="secure-v128-empty-icon" aria-hidden="true">+</div>` +
      `<h2>Select a Full Network member</h2>` +
      `<p>Recipient cards come from the authenticated viewer-private Full Directory. Message transport is not active in V1.28B.</p>` +
      `<div class="secure-v128-flow"><span>Full Directory alias</span><b>then</b><span>V1.27 recipient capability</span><b>then</b><span>V1.28 crypto package</span></div>` +
      `</section>`;
  }

  return `<section class="secure-v128-thread">` +
    `<header class="secure-v128-thread-header"><div class="secure-v128-person">` +
    `<span class="secure-v128-avatar" aria-hidden="true">${escapeHtml(initial(recipient))}</span>` +
    `<div><h2>${escapeHtml(displayName(recipient))}</h2>` +
    `<p>Current Full member - viewer-private recipient</p></div></div>` +
    `<span class="secure-v128-lock-pill">Secure messaging planned</span></header>` +
    `<div class="secure-v128-thread-notice"><strong>V1.28B selection only</strong>` +
    `<p>This selection stays in browser memory. No recipient capability, crypto package, message, ciphertext, relay event, or database write is created.</p></div>` +
    `<div class="secure-v128-selected-card"><span>Selected viewer-private alias</span>` +
    `<code>${escapeHtml(aliasSummary(recipient.alias))}</code>` +
    `<small>Raw participant identity is not displayed.</small></div>` +
    `<form class="secure-v128-composer" data-secure-v128-inert-composer>` +
    `<label class="sr-only" for="secure-v128-message">Message</label>` +
    `<textarea id="secure-v128-message" disabled placeholder="Encrypted messaging will be enabled after device-key and crypto phases."></textarea>` +
    `<button type="submit" disabled aria-label="Send disabled">Send</button>` +
    `<div class="secure-v128-composer-meta"><span>Future: encrypt on this device</span><span>Transport disabled in V1.28B</span></div>` +
    `</form></section>`;
};

export function renderSecureMessagingAuthenticatedShell(
  snapshot,
  {
    selectedAlias = null,
    filter = ""
  } = {}
) {
  if (
    !plainObject(snapshot) ||
    !["available", "restricted", "unavailable"].includes(snapshot.state) ||
    !Array.isArray(snapshot.recipients)
  ) {
    throw new TypeError("invalid secure messaging snapshot");
  }

  return `<section class="page secure-v128-page" data-secure-messaging-v128>` +
    `<header class="secure-v128-heading"><div><p class="eyebrow">Private Full Network</p>` +
    `<h1>Messages</h1><p>Choose a current Full member without exposing raw participant identity in the ordinary messaging interface.</p></div>` +
    `<button class="secure-v128-primary" type="button" data-secure-v128-focus-search>+ New message</button></header>` +
    `<div class="secure-v128-device"><span class="secure-v128-device-icon" aria-hidden="true">D</span>` +
    `<div><strong>Device encryption not connected yet</strong>` +
    `<p>V1.28C will add a dedicated device encryption key. Internal Social messages will not require a Nostr browser extension.</p></div>` +
    `<span class="secure-v128-stage">V1.28B</span></div>` +
    `<div class="secure-v128-layout"><aside class="secure-v128-list">` +
    `<div class="secure-v128-list-title"><div><strong>New conversation</strong><small>Full-to-Full only</small></div>` +
    `<span>${snapshot.state === "available" ? snapshot.recipients.length : 0}</span></div>` +
    `<label class="secure-v128-search"><span aria-hidden="true">S</span>` +
    `<input type="search" autocomplete="off" maxlength="120" value="${escapeHtml(filter)}" placeholder="Search private labels" data-secure-v128-search aria-label="Search private labels and aliases"></label>` +
    `<div class="secure-v128-recipient-stack" data-secure-v128-recipient-stack>` +
    renderRecipientPicker(snapshot, selectedAlias, filter) +
    `</div><div class="secure-v128-list-footer"><strong>Privacy boundary</strong>` +
    `<p>The browser receives viewer-private aliases only. Device-local labels are never sent by this shell.</p></div></aside>` +
    `<div class="secure-v128-thread-panel" data-secure-v128-thread-panel>` +
    renderThread(snapshot, selectedAlias) +
    `</div></div>` +
    `<section class="secure-v128-principles">` +
    `<article><span>01</span><strong>Real authenticated session</strong><p>The shell runs only inside the existing Social login context.</p></article>` +
    `<article><span>02</span><strong>Real Full Directory</strong><p>Recipient cards come from the same-origin authenticated BFF.</p></article>` +
    `<article><span>03</span><strong>Private labels</strong><p>Labels are read from this device and never become recipient identity.</p></article>` +
    `<article><span>04</span><strong>No transport yet</strong><p>No message or cryptographic operation is activated in this phase.</p></article>` +
    `</section></section>`;
}

export function bindSecureMessagingShell(root, {
  browser = globalThis.window,
  fetchImpl = globalThis.fetch,
  labelStore = createBrowserPrivateLabelStore(browser)
} = {}) {
  if (
    !root?.querySelector ||
    typeof browser?.addEventListener !== "function" ||
    typeof fetchImpl !== "function" ||
    !labelStore ||
    typeof labelStore.read !== "function"
  ) {
    return Object.freeze({ active: false });
  }

  const appPage = root.querySelector("#app-page");
  if (!appPage) return Object.freeze({ active: false });

  let rendering = false;
  let selectedAlias = null;
  let filter = "";
  let snapshot = null;
  let routeGeneration = 0;

  const isMessagesRoute = () =>
    browser.location?.hash === "#/messages";

  const currentAccess = () =>
    root.body?.getAttribute?.("data-access") ?? null;

  const paint = () => {
    if (!isMessagesRoute() || !snapshot) return;
    appPage.innerHTML = renderSecureMessagingAuthenticatedShell(snapshot, {
      selectedAlias,
      filter
    });
  };

  const load = async () => {
    if (rendering || !isMessagesRoute()) return false;

    const access = currentAccess();
    if (!access) return false;

    rendering = true;
    const generation = routeGeneration;

    try {
      snapshot = await loadSecureMessagingSnapshot({
        access,
        fetchImpl,
        labelStore
      });

      if (
        generation !== routeGeneration ||
        !isMessagesRoute() ||
        currentAccess() !== access
      ) {
        return false;
      }

      selectedAlias = null;
      filter = "";
      paint();
      return true;
    } finally {
      rendering = false;
    }
  };

  const schedule = () => {
    queueMicrotask(() => {
      if (!isMessagesRoute()) return;

      const access = currentAccess();
      if (!access) return;

      if (
        appPage.querySelector("[data-secure-messaging-v128]") &&
        snapshot
      ) {
        return;
      }

      if (
        snapshot &&
        ((access === "full" && snapshot.state === "available") ||
          (access !== "full" && snapshot.state === "restricted"))
      ) {
        paint();
        return;
      }

      void load();
    });
  };

  appPage.addEventListener?.("click", (event) => {
    const button = event.target?.closest?.("button");
    if (!button || !isMessagesRoute()) return;

    if (button.hasAttribute("data-secure-v128-focus-search")) {
      appPage.querySelector("[data-secure-v128-search]")?.focus?.();
      return;
    }

    const alias = button.getAttribute("data-secure-v128-recipient");
    if (
      typeof alias === "string" &&
      snapshot?.state === "available" &&
      snapshot.recipients.some((recipient) => recipient.alias === alias)
    ) {
      selectedAlias = alias;
      paint();
    }
  });

  appPage.addEventListener?.("input", (event) => {
    if (
      !isMessagesRoute() ||
      !event.target?.hasAttribute?.("data-secure-v128-search") ||
      typeof event.target.value !== "string"
    ) return;

    filter = event.target.value
      .normalize("NFKC")
      .replace(/[\u0000-\u001f\u007f]/g, "")
      .replace(/\s+/g, " ")
      .slice(0, 120);

    paint();

    const input = appPage.querySelector("[data-secure-v128-search]");
    if (input) {
      input.focus?.();
      try {
        input.setSelectionRange?.(filter.length, filter.length);
      } catch {
        // Selection support is optional.
      }
    }
  });

  appPage.addEventListener?.("submit", (event) => {
    if (event.target?.hasAttribute?.("data-secure-v128-inert-composer")) {
      event.preventDefault?.();
    }
  });

  browser.addEventListener("hashchange", () => {
    routeGeneration += 1;
    selectedAlias = null;
    filter = "";
    snapshot = null;
    schedule();
  });

  const observer = typeof MutationObserver === "function"
    ? new MutationObserver(() => schedule())
    : null;

  observer?.observe(appPage, {
    childList: true,
    subtree: false
  });

  schedule();

  return Object.freeze({
    active: true,
    reload: load,
    repaint: paint,
    snapshot: () => snapshot,
    selectedAlias: () => selectedAlias,
    disconnect: () => observer?.disconnect()
  });
}

export function bootstrapSecureMessagingV128(
  root = globalThis.document,
  browser = globalThis.window,
  fetchImpl = globalThis.fetch
) {
  if (
    !root?.documentElement?.hasAttribute?.("data-hodlxxi-authenticated-entry")
  ) {
    return false;
  }

  bindSecureMessagingShell(root, {
    browser,
    fetchImpl
  });
  return true;
}

// Production route ownership belongs to auth-entry.mjs.
// The explicit bootstrap remains exported for isolated use only.
