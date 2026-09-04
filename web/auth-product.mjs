import {
  escapeHtml,
  renderPageFrame,
  renderStatusBadge,
  renderUnavailableState
} from "./components.mjs?v=1.28.1";

import {
  renderSecureMessagingAuthenticatedShell
} from "./secure-messaging-v128.mjs?v=1.28.1";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const CANONICAL_EVENT_ID = /^[0-9a-f]{64}$/;
const UNSAFE_PRIVATE_ALIAS = /^(?:[0-9a-f]{64}|npub1|nprofile1|nsec1|xpub|tpub|ypub|zpub|vpub|xprv|tprv|yprv|zprv|vprv|bc1|tb1)/i;
const BITCOIN_BASE58_ADDRESS = /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const PRODUCT_STATUSES = new Set(["limited", "full"]);
const PUBLIC_READ_STATES = new Set([
  "loading",
  "available",
  "empty",
  "unavailable"
]);
const SIGNER_STATES = new Set([
  "disabled",
  "disconnected",
  "connecting",
  "connected",
  "mismatch",
  "unavailable"
]);
const PUBLISH_OPERATIONS = new Set([
  "idle",
  "publishing-profile",
  "publishing-note",
  "published-profile",
  "published-note",
  "failed-profile",
  "failed-note"
]);
const EMPTY = Object.freeze([]);
const DEFAULT_PUBLIC_READ = Object.freeze({
  relayHost: null,
  profileState: "unavailable",
  profile: null,
  notesState: "unavailable",
  notes: EMPTY
});
const DEFAULT_PUBLIC_WRITE = Object.freeze({
  relayHost: null,
  signerState: "disabled",
  operation: "idle"
});
const FULL_DIRECTORY_STATES = new Set([
  "loading",
  "available",
  "unavailable"
]);
const DEFAULT_FULL_DIRECTORY = Object.freeze({
  state: "unavailable",
  participants: EMPTY
});

const plainObject = (value) =>
  Boolean(value) &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const exactKeys = (value, expected) => {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length &&
    sorted.every((name, index) => keys[index] === name);
};

const validIsoTimestamp = (value) => {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) return false;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) && timestamp.toISOString() === value;
};

const normalizePublicRead = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, [
      "notes",
      "notesState",
      "profile",
      "profileState",
      "relayHost"
    ]) ||
    !PUBLIC_READ_STATES.has(value.profileState) ||
    !PUBLIC_READ_STATES.has(value.notesState) ||
    !(
      value.relayHost === null ||
      (
        typeof value.relayHost === "string" &&
        value.relayHost.length > 0 &&
        value.relayHost.length <= 255 &&
        !/[\u0000-\u0020\u007f]/.test(value.relayHost)
      )
    ) ||
    !Array.isArray(value.notes)
  ) {
    throw new TypeError("invalid authenticated public read");
  }

  let profile = null;
  if (value.profileState === "available") {
    if (
      !plainObject(value.profile) ||
      !exactKeys(value.profile, [
        "about",
        "createdAt",
        "displayName",
        "eventId"
      ]) ||
      !CANONICAL_EVENT_ID.test(value.profile.eventId) ||
      !validIsoTimestamp(value.profile.createdAt) ||
      !(
        value.profile.displayName === null ||
        (
          typeof value.profile.displayName === "string" &&
          value.profile.displayName.length > 0 &&
          value.profile.displayName.length <= 80
        )
      ) ||
      !(
        value.profile.about === null ||
        (
          typeof value.profile.about === "string" &&
          value.profile.about.length > 0 &&
          value.profile.about.length <= 280
        )
      )
    ) {
      throw new TypeError("invalid authenticated public read");
    }
    profile = Object.freeze({ ...value.profile });
  } else if (value.profile !== null) {
    throw new TypeError("invalid authenticated public read");
  }

  const notes = [];
  for (const note of value.notes) {
    if (
      !plainObject(note) ||
      !exactKeys(note, ["body", "createdAt", "id"]) ||
      !CANONICAL_EVENT_ID.test(note.id) ||
      typeof note.body !== "string" ||
      note.body.length > 5_000 ||
      !validIsoTimestamp(note.createdAt)
    ) {
      throw new TypeError("invalid authenticated public read");
    }
    notes.push(Object.freeze({ ...note }));
  }

  if (
    notes.length > 10 ||
    (value.notesState === "available" && notes.length === 0) ||
    (value.notesState !== "available" && notes.length !== 0) ||
    (
      [value.profileState, value.notesState].some((state) =>
        ["available", "empty"].includes(state)
      ) && value.relayHost === null
    )
  ) {
    throw new TypeError("invalid authenticated public read");
  }

  return Object.freeze({
    relayHost: value.relayHost,
    profileState: value.profileState,
    profile,
    notesState: value.notesState,
    notes: Object.freeze(notes)
  });
};

const normalizePublicWrite = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["operation", "relayHost", "signerState"]) ||
    !SIGNER_STATES.has(value.signerState) ||
    !PUBLISH_OPERATIONS.has(value.operation) ||
    !(
      value.relayHost === null ||
      (
        typeof value.relayHost === "string" &&
        value.relayHost.length > 0 &&
        value.relayHost.length <= 255 &&
        !/[\u0000-\u0020\u007f]/.test(value.relayHost)
      )
    ) ||
    (value.signerState === "disabled") !== (value.relayHost === null) ||
    (
      value.operation !== "idle" &&
      value.signerState !== "connected"
    )
  ) {
    throw new TypeError("invalid authenticated public write");
  }

  return Object.freeze({
    relayHost: value.relayHost,
    signerState: value.signerState,
    operation: value.operation
  });
};

const normalizeFullDirectory = (value) => {
  if (
    !plainObject(value) ||
    !exactKeys(value, ["participants", "state"]) ||
    !FULL_DIRECTORY_STATES.has(value.state) ||
    !Array.isArray(value.participants) ||
    value.participants.length > 4096 ||
    (value.state !== "available" && value.participants.length !== 0)
  ) {
    throw new TypeError("invalid authenticated Full directory");
  }
  const participants = [];
  const aliases = new Set();
  for (const participant of value.participants) {
    if (
      !plainObject(participant) ||
      !exactKeys(participant, ["alias"]) ||
      typeof participant.alias !== "string" ||
      !/^[A-Za-z0-9._~-]{1,128}$/.test(participant.alias) ||
      UNSAFE_PRIVATE_ALIAS.test(participant.alias) ||
      BITCOIN_BASE58_ADDRESS.test(participant.alias) ||
      /^\d{7,15}$/.test(participant.alias) ||
      participant.alias.includes("@") ||
      aliases.has(participant.alias)
    ) {
      throw new TypeError("invalid authenticated Full directory");
    }
    aliases.add(participant.alias);
    participants.push(Object.freeze({ alias: participant.alias }));
  }
  return Object.freeze({
    state: value.state,
    participants: Object.freeze(participants)
  });
};

const normalizePrivateLabels = (value, fullDirectory) => {
  if (
    !Array.isArray(value) ||
    value.length > 4096
  ) {
    throw new TypeError("invalid private labels");
  }

  const allowedAliases = new Set(
    fullDirectory.participants.map(
      (participant) => participant.alias
    )
  );

  const aliases = new Set();
  const labels = [];

  for (const record of value) {
    if (
      !plainObject(record) ||
      !exactKeys(record, ["alias", "label"]) ||
      typeof record.alias !== "string" ||
      !allowedAliases.has(record.alias) ||
      aliases.has(record.alias) ||
      typeof record.label !== "string" ||
      record.label.length === 0 ||
      record.label.length > 256 ||
      [...record.label].length > 64 ||
      /[\u0000-\u001f\u007f]/u.test(record.label) ||
      record.label.normalize("NFC") !== record.label ||
      record.label.trim() !== record.label ||
      /\s{2,}/u.test(record.label)
    ) {
      throw new TypeError("invalid private labels");
    }

    aliases.add(record.alias);

    labels.push(
      Object.freeze({
        alias: record.alias,
        label: record.label
      })
    );
  }

  return Object.freeze(labels);
};

const privateLabelFor = (model, alias) =>
  model.privateLabels.find(
    (record) => record.alias === alias
  )?.label ?? null;

const shortKey = (subject) =>
  `${subject.slice(0, 8)}…${subject.slice(-6)}`;

const statusLabel = (status) =>
  status === "full" ? "Full Member" : "Limited User";

const statusDetail = (model) => {
  if (!model.authorityValid) {
    return "The external authority read was not accepted, so Social is operating as Limited.";
  }

  return model.status === "full"
    ? "Current Full access was projected from the external HODLXXI authority for this session."
    : "Current Limited access was projected from the external HODLXXI authority for this session.";
};

const hasFullNetworkAccess = (model) =>
  model.authorityValid === true && model.status === "full";

const publicProfileName = (model) =>
  model.publicRead.profileState === "available" &&
  model.publicRead.profile?.displayName
    ? model.publicRead.profile.displayName
    : "Your HODLXXI identity";

const publicProfileAbout = (model) =>
  model.publicRead.profileState === "available"
    ? model.publicRead.profile?.about
    : null;

const avatarInitial = (model) => {
  const first = [...publicProfileName(model).trim()][0] ?? "H";
  return first.toUpperCase().slice(0, 2);
};

const publicPostCount = (model) =>
  ["available", "empty"].includes(model.publicRead.notesState)
    ? String(model.publicRead.notes.length)
    : "—";

const publicReadSource = (model) =>
  model.publicRead.relayHost
    ? `Signed Nostr events · ${model.publicRead.relayHost}`
    : "Signed Nostr events · source unavailable";

const writeBusy = (model) =>
  model.publicWrite.operation.startsWith("publishing-");

const publishFeedback = (model, type) => {
  if (model.publicWrite.operation === `published-${type}`) {
    return `<p class="publish-feedback publish-feedback-success" role="status">Published to ${escapeHtml(model.publicWrite.relayHost)} after local signature verification.</p>`;
  }
  if (model.publicWrite.operation === `failed-${type}`) {
    return `<p class="publish-feedback publish-feedback-error" role="status">Publication was not accepted. No membership or authority state changed.</p>`;
  }
  if (model.publicWrite.operation === `publishing-${type}`) {
    return `<p class="publish-feedback" role="status">Waiting for signer approval and one relay acknowledgement…</p>`;
  }
  return "";
};

const signerControl = (model) => {
  const state = model.publicWrite.signerState;
  if (state === "disabled") {
    return `<p class="signer-state signer-state-disabled">Publishing relay not configured.</p>`;
  }
  if (state === "connected") {
    return `<p class="signer-state signer-state-connected"><span>✓</span> External signer matched this session key. Every action rechecks.</p>`;
  }

  const detail = state === "mismatch"
    ? "The extension key does not match this authenticated session."
    : state === "unavailable"
      ? "A compatible NIP-07 signer was not accepted."
      : state === "connecting"
        ? "Waiting for extension approval…"
        : "Connect an external signer to publish as this exact key.";

  return `<div class="signer-connect"><p class="signer-state">${escapeHtml(detail)}</p>` +
    `<button id="connect-authenticated-signer" class="product-action" type="button"${state === "connecting" ? " disabled" : ""}>${state === "connecting" ? "Connecting…" : "Connect signer"}</button></div>`;
};

const publicTimestamp = (value) =>
  `${value.slice(0, 10)} ${value.slice(11, 16)} UTC`;

const actionLink = (href, label, secondary = false) =>
  `<a class="product-action${secondary ? " product-action-secondary" : ""}" href="${href}">${escapeHtml(label)}</a>`;

const metric = (value, label, detail) =>
  `<div class="product-metric"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span><small>${escapeHtml(detail)}</small></div>`;

const surfaceEmpty = ({ icon, title, detail, actions = "" }) =>
  `<article class="product-empty-state">` +
  `<div class="product-empty-icon" aria-hidden="true">${escapeHtml(icon)}</div>` +
  `<div><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p>` +
  `${actions ? `<div class="product-actions">${actions}</div>` : ""}</div>` +
  `</article>`;

const publicNoteCard = (model, note) =>
  `<article class="post-card public-note-card">` +
  `<header><div class="avatar" aria-hidden="true">${escapeHtml(avatarInitial(model))}</div>` +
  `<div><strong class="post-author">${escapeHtml(publicProfileName(model))}</strong>` +
  `<span class="verified-event-label">Verified event</span>` +
  `<p class="post-meta">${escapeHtml(publicTimestamp(note.createdAt))} · Public</p></div></header>` +
  `<p class="post-body public-note-body">${note.body ? escapeHtml(note.body) : "<em>Empty signed note</em>"}</p>` +
  `<footer class="public-note-proof"><span>${escapeHtml(shortKey(note.id))}</span>` +
  `<span>Read-only · signature checked</span></footer></article>`;

const publicNotesSurface = (model, profile = false) => {
  if (model.publicRead.notesState === "available") {
    return model.publicRead.notes
      .map((note) => publicNoteCard(model, note))
      .join("");
  }

  if (model.publicRead.notesState === "loading") {
    return surfaceEmpty({
      icon: "…",
      title: "Reading signed public posts",
      detail: "Social is performing one bounded read for this exact authenticated public key."
    });
  }

  if (model.publicRead.notesState === "empty") {
    return surfaceEmpty({
      icon: "◎",
      title: profile ? "No signed public posts on this profile" : "No signed public posts found",
      detail: `The explicit relay ${model.publicRead.relayHost} completed the bounded read without returning a verified kind 1 event for this key.`
    });
  }

  return surfaceEmpty({
    icon: "!",
    title: "Public posts unavailable",
    detail: "The bounded relay read could not be accepted. Social displays no unverified or off-subject event data."
  });
};

const membershipStrip = (model) =>
  `<section class="membership-strip" aria-label="Current membership">` +
  `<div class="membership-mark" aria-hidden="true">✓</div>` +
  `<div class="membership-copy"><span>Current membership</span>` +
  `<strong>${escapeHtml(statusLabel(model.status))}</strong>` +
  `<small>${model.authorityValid ? "External authority · checked for this session" : "Fail-closed Limited · authority unavailable"}</small></div>` +
  `${renderStatusBadge(model.status)}` +
  `<a href="#/trust">View details <span aria-hidden="true">→</span></a>` +
  `</section>`;

const authenticatedComposer = (model) => {
  const connected = model.publicWrite.signerState === "connected";
  const busy = writeBusy(model);

  return `<section class="composer-card authenticated-composer" aria-label="Post composer">` +
  `<div class="composer-head"><div class="avatar" aria-hidden="true">${escapeHtml(avatarInitial(model))}</div>` +
  `<div><strong>${escapeHtml(publicProfileName(model))}</strong>${renderStatusBadge(model.status)}` +
  `<p>Authenticated as ${escapeHtml(shortKey(model.subject))}</p></div></div>` +
  `<form id="authenticated-note-publisher">` +
  `<label class="sr-only" for="authenticated-note-content">Public post</label>` +
  `<textarea id="authenticated-note-content" name="content" maxlength="5000" required${connected ? "" : " disabled"} placeholder="What’s on your mind?"></textarea>` +
  `<div class="composer-actions"><div class="local-tools" aria-label="Planned post attachments">` +
  `<span>Image</span><span>Poll</span><span>Article</span></div>` +
  `<span class="composer-audience">Audience · Public</span>` +
  `<button type="submit"${connected && !busy ? "" : " disabled"}>${busy ? "Publishing…" : "Post"}</button></div></form>` +
  `${signerControl(model)}${publishFeedback(model, "note")}` +
  `<p class="notice">Social never receives private-key material. Each post requires explicit approval in an external signer and one relay acknowledgement. Publishing cannot grant membership or covenant authority.</p>` +
  `</section>`;
};

const productGuide = (model) =>
  `<article class="post-card product-guide-card">` +
  `<header><div class="avatar product-avatar" aria-hidden="true">H</div>` +
  `<div><strong class="post-author">HODLXXI Social</strong>` +
  `<span class="product-guide-label">Product guide</span>` +
  `<p class="post-meta">Your authenticated workspace · current session</p></div></header>` +
  `<p class="post-body">Your public-key session and ${escapeHtml(statusLabel(model.status))} access are active. Signed Nostr profile data and posts remain separate from HODLXXI membership authority.</p>` +
  `<div class="guide-steps">` +
  `<a href="#/profile/${escapeHtml(model.subject)}"><span>1</span><strong>Review identity</strong><small>Session-bound public key</small></a>` +
  `<a href="#/circle"><span>2</span><strong>Open My Circle</strong><small>Friends and two-hop reach</small></a>` +
  `<a href="#/trust"><span>3</span><strong>Inspect trust</strong><small>External membership source</small></a>` +
  `</div></article>`;

const homePage = (model) =>
  renderPageFrame({
    title: "Home",
    className: "home-page authenticated-home",
    content:
      `<div class="home-heading"><div><p class="eyebrow">Authenticated network</p>` +
      `<h2>Welcome back</h2><p>Your Social workspace is bound to ${escapeHtml(shortKey(model.subject))}.</p></div>` +
      `<span class="source-pill"><i></i> Session active</span></div>` +
      membershipStrip(model) +
      authenticatedComposer(model) +
      `<div class="feed-toolbar"><div><strong>Your public posts</strong><span>${escapeHtml(publicReadSource(model))}</span></div>` +
      `<div class="feed-filter" aria-label="Feed scope"><span class="active">Your posts</span><span>Network later</span></div></div>` +
      `<section class="feed-stack" aria-label="Verified public posts">${publicNotesSurface(model)}` +
      `${productGuide(model)}</section>`
  });

const profileHero = (model, compact = false) =>
  `<article class="authenticated-profile${compact ? " authenticated-profile-compact" : ""}">` +
  `${compact ? "" : '<div class="profile-cover" aria-hidden="true"></div>'}` +
  `<div class="profile-identity"><div class="avatar avatar-large" aria-hidden="true">${escapeHtml(avatarInitial(model))}</div>` +
  `<div><p class="eyebrow">Authenticated participant</p>` +
  `<h2>${escapeHtml(publicProfileName(model))}</h2><div class="profile-badges">${renderStatusBadge(model.status)}<span class="session-chip">Session authenticated</span></div></div></div>` +
  `<p class="key">${escapeHtml(model.subject)}</p>` +
  `${compact ? "" : `<p class="profile-lead">This is the only participant identity accepted from the current Social session. ${escapeHtml(publicReadSource(model))}. Public presentation remains separate from membership authority.</p>`}` +
  `<div class="profile-links">` +
  actionLink(`#/profile/${escapeHtml(model.subject)}`, compact ? "Open profile" : "Profile", compact) +
  `${compact ? actionLink("#/trust", "Trust details", true) : ""}</div>` +
  `</article>`;

const profileEditor = (model) => {
  const connected = model.publicWrite.signerState === "connected";
  const busy = writeBusy(model);
  const displayName = publicProfileName(model) === "Your HODLXXI identity"
    ? ""
    : publicProfileName(model);
  const about = publicProfileAbout(model) ?? "";

  return `<section class="card authenticated-profile-editor"><p class="eyebrow">Publish profile</p>` +
    `<h2>Public presentation</h2><form id="authenticated-profile-publisher">` +
    `<label for="authenticated-profile-name">Display name</label>` +
    `<input id="authenticated-profile-name" name="displayName" maxlength="80" value="${escapeHtml(displayName)}"${connected ? "" : " disabled"}>` +
    `<label for="authenticated-profile-about">Bio</label>` +
    `<textarea id="authenticated-profile-about" name="about" maxlength="280"${connected ? "" : " disabled"}>${escapeHtml(about)}</textarea>` +
    `<button class="product-action" type="submit"${connected && !busy ? "" : " disabled"}>${busy ? "Publishing…" : "Publish profile"}</button>` +
    `</form>${signerControl(model)}${publishFeedback(model, "profile")}` +
    `<p class="notice">Only display name and bio are included in the public kind 0 event. Pictures, NIP-05 claims, links and unknown metadata are not published here.</p></section>`;
};

const profilePage = (model) =>
  renderPageFrame({
    title: "Profile",
    className: "authenticated-profile-page",
    content:
      profileHero(model) +
      `<dl class="profile-stat-row">` +
      `<div><dt>Posts</dt><dd>${escapeHtml(publicPostCount(model))}</dd></div><div><dt>Friends</dt><dd>0</dd></div><div><dt>Circles</dt><dd>0</dd></div>` +
      `</dl>` +
      `<div class="profile-grid">` +
      `<section class="card"><p class="eyebrow">Public profile</p><h2>Profile details</h2>` +
      `<dl class="detail-list"><div><dt>Display name</dt><dd>${escapeHtml(model.publicRead.profileState === "loading" ? "Loading" : model.publicRead.profileState === "unavailable" ? "Unavailable" : model.publicRead.profile?.displayName ?? "Not published")}</dd></div>` +
      `<div><dt>Bio</dt><dd>${escapeHtml(publicProfileAbout(model) ?? (model.publicRead.profileState === "loading" ? "Loading" : model.publicRead.profileState === "unavailable" ? "Unavailable" : "Not published"))}</dd></div>` +
      `<div><dt>Public key</dt><dd>${escapeHtml(shortKey(model.subject))}</dd></div>` +
      `<div><dt>Read source</dt><dd>${escapeHtml(model.publicRead.relayHost ?? "Unavailable")}</dd></div></dl>` +
      `<p class="notice">A verified Nostr event proves control of its signing key. It does not grant HODLXXI membership or covenant trust.</p></section>` +
      `<section class="card"><p class="eyebrow">Membership</p><h2>${escapeHtml(statusLabel(model.status))}</h2>` +
      `<p>${escapeHtml(statusDetail(model))}</p>${actionLink("#/trust", "View trust details")}</section>` +
      `${profileEditor(model)}</div>` +
      `<section class="profile-public-posts" aria-label="Profile public posts">` +
      `<div class="feed-toolbar"><div><strong>Public posts</strong><span>${escapeHtml(publicReadSource(model))}</span></div></div>` +
      `${publicNotesSurface(model, true)}</section>`
  });

const circlePage = (model) =>
  renderPageFrame({
    title: "My Circle",
    content:
      `<section class="circle-product authenticated-circle"><div class="circle-heading"><div>` +
      `<p class="eyebrow">Social topology</p><h2>Your people, in context</h2>` +
      `<p>Friends define social reach. Sponsor and covenant relationships remain a separate evidence layer.</p></div>` +
      `<span class="source-pill"><i></i> Current session</span></div>` +
      `<div class="circle-mode-tabs" role="tablist" aria-label="Circle relationship view">` +
      `<span role="tab" aria-selected="true">Social</span><span role="tab" aria-selected="false">Sponsor</span>` +
      `<span role="tab" aria-selected="false">CRT</span><span role="tab" aria-selected="false">Bitcoin</span></div>` +
      `<div class="circle-canvas"><svg class="circle-graph" viewBox="0 0 800 520" role="img" aria-labelledby="auth-circle-title auth-circle-description">` +
      `<title id="auth-circle-title">My Circle social topology</title>` +
      `<desc id="auth-circle-description">The authenticated participant is centered. The direct-friend and two-hop rings currently contain no connected identities.</desc>` +
      `<circle class="ring-guide ring-guide-outer" cx="400" cy="260" r="220"/>` +
      `<circle class="ring-guide ring-guide-inner" cx="400" cy="260" r="130"/>` +
      `<g class="circle-node circle-node-center" transform="translate(400 260)"><circle r="46"/>` +
      `<text class="circle-initial" text-anchor="middle" y="7">YOU</text>` +
      `<text class="circle-label" text-anchor="middle" y="72">${escapeHtml(shortKey(model.subject))}</text></g>` +
      `</svg><div class="circle-ring-label circle-ring-direct">Direct friends</div>` +
      `<div class="circle-ring-label circle-ring-two-hop">Two-hop reach</div></div>` +
      `<div class="circle-legend" aria-label="Relationship legend"><span><i class="legend-friend"></i>Friend · social relationship</span>` +
      `<span><i class="legend-trust"></i>Sponsor · external provenance</span>` +
      `<span><i class="legend-reach"></i>Two hops · friends of friends</span></div>` +
      `<dl class="circle-summary"><div><dt>Direct friends</dt><dd>0</dd></div>` +
      `<div><dt>Two-hop reach</dt><dd>0</dd></div><div><dt>Selected circles</dt><dd>0</dd></div>` +
      `<div><dt>Visible trust links</dt><dd>0</dd></div></dl>` +
      surfaceEmpty({
        icon: "+",
        title: "Your circle starts here",
        detail: "No friend relationships are connected to this session yet. Friendship will remain separate from sponsor and covenant trust.",
        actions: actionLink("#/discover", "Discover people")
      }) +
      `</section>`
  });

const directoryPage = (model, title, mode) => {
  const descriptions = {
    friends: "Mutual social relationships connected to your public key.",
    discovery: "People reachable through one of your direct friends.",
    discover: "People, public posts and groups available under your current visibility policy."
  };
  const emptyTitles = {
    friends: "No direct friends yet",
    discovery: "No two-hop connections yet",
    discover: "Nothing to recommend yet"
  };

  return renderPageFrame({
    title,
    content:
      `<section class="directory-product"><div class="directory-toolbar"><div>` +
      `<p class="eyebrow">People</p><h2>${escapeHtml(title)}</h2><p>${escapeHtml(descriptions[mode])}</p></div>` +
      `<span class="result-count">0 visible</span></div>` +
      `<div class="directory-filters"><span class="active">All</span><span>${mode === "friends" ? "Recently active" : "Full Members"}</span><span>Limited Users</span></div>` +
      surfaceEmpty({
        icon: "◌",
        title: emptyTitles[mode],
        detail: mode === "discovery"
          ? "Two-hop discovery means friends of friends; it never means sponsor lineage."
          : "No permitted participant records are connected to the authenticated social dataset.",
        actions: mode === "discover"
          ? actionLink("#/search", "Search people")
          : actionLink("#/discover", "Open discovery")
      }) +
      `<p class="notice">Visible people and social reach cannot grant or prove membership, sponsorship or covenant trust.</p></section>`
  });
};

const privateAliasSummary = (alias) => {
  if (alias.length <= 22) return alias;
  return `${alias.slice(0, 10)}…${alias.slice(-8)}`;
};

const privateAliasInitials = (alias) => {
  const visible = [...alias]
    .filter((character) => /[A-Za-z0-9]/.test(character))
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return visible || "H";
};

const fullNetworkDirectory = (model) => {
  if (model.fullDirectory.state === "loading") {
    return surfaceEmpty({
      icon: "…",
      title: "Connecting to the private directory",
      detail: "Social is performing one authenticated, viewer-bound directory request."
    });
  }
  if (model.fullDirectory.state === "unavailable") {
    return surfaceEmpty({
      icon: "!",
      title: "Private directory unavailable",
      detail: "No participant information is shown when the private directory cannot be accepted."
    });
  }
  if (model.fullDirectory.participants.length === 0) {
    return surfaceEmpty({
      icon: "◌",
      title: "No other Full members are visible",
      detail: "The accepted viewer-private directory currently contains no other Full-member aliases."
    });
  }

  const count = model.fullDirectory.participants.length;
  const summary = `${count} other Full ${count === 1 ? "member" : "members"}`;

  return `<div class="full-network-directory-live">` +
    `<div class="full-network-directory-summary">` +
    `<strong>${escapeHtml(summary)}</strong>` +
    `<span>Current viewer-private directory</span>` +
    `</div>` +
    `<div class="full-network-members" aria-label="Viewer-private Full Network members">` +
    model.fullDirectory.participants.map((participant) => {
      const alias = participant.alias;
      const privateLabel = privateLabelFor(model, alias);

      return `<article class="full-network-member-card">` +
        `<div class="full-network-member-monogram" aria-hidden="true">${escapeHtml(privateAliasInitials(alias))}</div>` +
        `<div class="full-network-member-main">` +
        (
          privateLabel
            ? `<div class="full-network-private-label">` +
              `<strong>${escapeHtml(privateLabel)}</strong>` +
              `<small>Private label · this device only</small>` +
              `</div>`
            : ""
        ) +
        `<div class="full-network-member-heading">` +
        `<strong>Full Network member</strong>` +
        `<span class="full-network-member-status">Current Full</span>` +
        `</div>` +
        `<code title="${escapeHtml(alias)}">${escapeHtml(privateAliasSummary(alias))}</code>` +
        `<small>Viewer-private identifier</small>` +
        `<form class="full-network-private-label-form" data-private-label-alias="${escapeHtml(alias)}">` +
        `<label>` +
        `<span>Private label on this device</span>` +
        `<input name="label" maxlength="64" autocomplete="off" value="${escapeHtml(privateLabel ?? "")}" placeholder="e.g. Brother, Grandson, Ivan">` +
        `</label>` +
        `<button type="submit">Save</button>` +
        `</form>` +
        `<small class="full-network-private-label-help">Leave blank and save to remove. This label is not a profile name and is not sent to HODLXXI.</small>` +
        `</div>` +
        `</article>`;
    }).join("") +
    `</div>` +
    `<p class="full-network-directory-note">These identifiers are private presentation aliases for this viewer. They are not participant public keys, names, payment addresses, or identity-resolution handles.</p>` +
    `</div>`;
};

const fullNetworkPage = (model) =>
  renderPageFrame({
    eyebrow: "Private member network",
    title: "Full Network",
    className: "full-network-page",
    content:
      `<section class="full-network-product">` +
      `<div class="full-network-hero"><div><p class="eyebrow">HODLXXI Full members</p>` +
      `<h2>The private HODLXXI Full-member network</h2>` +
      `<p>This authenticated area is reserved for participants with a current accepted Full authority projection.</p></div>` +
      `<div class="full-network-access"><span>Current access</span><strong>Full</strong></div></div>` +
      `<article class="full-network-privacy"><div class="full-network-privacy-mark" aria-hidden="true">◉</div>` +
      `<div><p class="eyebrow">Privacy boundary</p><h2>Participant identity keys are not exposed here</h2>` +
      `<p>This browser shell does not receive or render other participants’ public keys or private directory records.</p></div></article>` +
      `<section class="full-network-directory" aria-label="Full Network directory state">` +
      `<div><p class="eyebrow">Full Directory</p><h2>People in your Full Network</h2>` +
      `<p>Only current Full participants accepted for this authenticated viewer are shown here.</p></div>` +
      fullNetworkDirectory(model) +
      `</section></section>`
  });

const searchPage = (model, query = "") => {
  const normalized = String(query).trim().toLowerCase().slice(0, 120);
  const matchesSelf = Boolean(normalized) && [
    "you",
    "your profile",
    "hodlxxi",
    "authenticated participant"
  ].some((value) => value.includes(normalized) || normalized.includes(value)) ||
    Boolean(normalized && model.subject.startsWith(normalized));

  const result = matchesSelf
    ? `<section class="search-results"><p class="search-summary">1 permitted result</p>` +
      `<a class="search-card search-person" href="#/profile/${escapeHtml(model.subject)}">` +
      `<span class="avatar" aria-hidden="true">H</span><span><strong>Your HODLXXI identity</strong>` +
      `<small>${escapeHtml(shortKey(model.subject))} · ${escapeHtml(statusLabel(model.status))}</small></span></a></section>`
    : normalized
      ? surfaceEmpty({
          icon: "⌕",
          title: "No permitted matches",
          detail: "The current authenticated dataset contains only your session identity. Network results will appear after public social data is connected."
        })
      : `<div class="search-intro"><strong>Search your Social network</strong>` +
        `<p>Try “you” or the beginning of your public key. People, posts and groups will share this surface as sources are connected.</p></div>`;

  return renderPageFrame({
    title: "Search",
    content:
      `<section class="search-product authenticated-search"><form id="authenticated-search" class="search-bar">` +
      `<label class="sr-only" for="authenticated-search-query">Search people, posts and groups</label>` +
      `<input id="authenticated-search-query" name="q" value="${escapeHtml(normalized)}" maxlength="120" autocomplete="off" placeholder="Search people, posts, groups, or public keys">` +
      `<button type="submit">Search</button>${normalized ? '<a href="#/search" aria-label="Clear search">Clear</a>' : ""}</form>` +
      `${result}</section>`
  });
};

const secureMessagingSnapshot = (model) => {
  if (!hasFullNetworkAccess(model)) {
    return Object.freeze({
      state: "restricted",
      recipients: EMPTY
    });
  }

  if (model.fullDirectory.state !== "available") {
    return Object.freeze({
      state: "unavailable",
      recipients: EMPTY
    });
  }

  const recipients = model.fullDirectory.participants.map(
    (participant) => Object.freeze({
      alias: participant.alias,
      label: privateLabelFor(model, participant.alias)
    })
  );

  return Object.freeze({
    state: "available",
    recipients: Object.freeze(recipients)
  });
};

const messagesPage = (model) =>
  renderSecureMessagingAuthenticatedShell(
    secureMessagingSnapshot(model)
  );


const groupsPage = () =>
  renderPageFrame({
    title: "Groups",
    content:
      `<section class="groups-product"><div class="directory-toolbar"><div><p class="eyebrow">Communities</p>` +
      `<h2>Your groups</h2><p>Shared social spaces with explicit membership and moderation scope.</p></div>` +
      `<span class="result-count">0 groups</span></div>` +
      `<div class="product-metrics">${metric("0", "Memberships", "Visible to you")}${metric("0", "Unread", "Current session")}${metric("0", "Invitations", "Permitted")}</div>` +
      surfaceEmpty({
        icon: "◇",
        title: "No accessible groups",
        detail: "Group records and encrypted delivery are not connected to the authenticated dataset yet.",
        actions: actionLink("#/discover", "Discover spaces")
      }) +
      `<p class="notice">Group membership is a social permission. It cannot create Full status or covenant trust.</p></section>`
  });

const notificationsPage = () =>
  renderPageFrame({
    title: "Notifications",
    content:
      `<section class="notifications-product"><div class="notification-toolbar"><div><p class="eyebrow">Updates</p>` +
      `<h2>Notifications</h2><p>Identity-safe activity addressed to this session.</p></div>` +
      `<span class="result-count">0 unread</span></div>` +
      surfaceEmpty({
        icon: "○",
        title: "You’re all caught up",
        detail: "No permitted network notifications are connected to this session."
      }) +
      `</section>`
  });

const activityPage = (model) =>
  renderPageFrame({
    title: "Activity",
    content:
      `<section class="activity-product"><div class="directory-toolbar"><div><p class="eyebrow">Session activity</p>` +
      `<h2>What’s current</h2><p>Product facts derived from this authenticated page session.</p></div></div>` +
      `<div class="activity-timeline"><article><span class="activity-dot"></span><div><strong>Social session authenticated</strong>` +
      `<p>${escapeHtml(shortKey(model.subject))} is the sole viewer for this workspace.</p><small>Current browser session</small></div></article>` +
      `<article><span class="activity-dot activity-dot-success"></span><div><strong>${escapeHtml(statusLabel(model.status))} access projected</strong>` +
      `<p>${escapeHtml(statusDetail(model))}</p><small>Read-only HODLXXI authority</small></div></article>` +
      `<article><span class="activity-dot"></span><div><strong>Public Nostr read ${model.publicRead.notesState === "available" || model.publicRead.notesState === "empty" ? "completed" : model.publicRead.notesState}</strong>` +
      `<p>${escapeHtml(publicReadSource(model))}. ${escapeHtml(publicPostCount(model))} accepted public posts.</p><small>One-shot browser read · ${model.publicWrite.relayHost ? "explicit external-signer publishing available" : "no writes"}</small></div></article></div>` +
      `<p class="notice">This is session context, not social engagement telemetry or a trust score.</p></section>`
  });

const trustPage = (model) =>
  renderPageFrame({
    title: "Trust",
    className: "authenticated-trust-page",
    content:
      `<section class="trust-hero"><div class="trust-seal" aria-hidden="true">✓</div>` +
      `<div><p class="eyebrow">Membership card</p><h2>${escapeHtml(statusLabel(model.status))}</h2>` +
      `<p>${escapeHtml(statusDetail(model))}</p></div>${renderStatusBadge(model.status)}</section>` +
      `<div class="trust-grid"><section class="card"><p class="eyebrow">Current verdict</p>` +
      `<dl class="detail-list"><div><dt>Status</dt><dd>${escapeHtml(statusLabel(model.status))}</dd></div>` +
      `<div><dt>Source</dt><dd>External HODLXXI authority</dd></div>` +
      `<div><dt>Scope</dt><dd>Current Social session</dd></div>` +
      `<div><dt>Freshness</dt><dd>${model.authorityValid ? "Accepted on page load" : "Unavailable · Limited fallback"}</dd></div>` +
      `<div><dt>Subject</dt><dd>${escapeHtml(shortKey(model.subject))}</dd></div></dl></section>` +
      `<section class="card"><p class="eyebrow">Boundary</p><h2>Relationships stay distinct</h2>` +
      `<ul class="boundary-list"><li><span>✓</span> Authentication binds this public key.</li>` +
      `<li><span>✓</span> Membership is read from an external authority.</li>` +
      `<li><span>—</span> Friendship is separate social context.</li>` +
      `<li><span>—</span> No trust score or elevated role is inferred.</li></ul></section></div>` +
      `<section class="evidence-card"><div><p class="eyebrow">Evidence detail</p><h2>Session-bound authority projection</h2>` +
      `<p>The product consumes only the current Limited/Full result for the exact authenticated subject. It does not issue, upgrade or persist membership.</p></div>` +
      `<code>${escapeHtml(model.subject)}</code></section>`
  });

const settingsPage = (model) =>
  renderPageFrame({
    title: "Settings",
    content:
      `<section class="settings-product"><div class="directory-toolbar"><div><p class="eyebrow">Account controls</p>` +
      `<h2>Social settings</h2><p>Identity, privacy, relays and portability stay explicit.</p></div></div>` +
      `<div class="settings-grid">` +
      `<article class="settings-card"><span class="settings-icon">⌁</span><div><strong>Identity & session</strong>` +
      `<p>${escapeHtml(shortKey(model.subject))} · authenticated</p></div><a href="#/profile/${escapeHtml(model.subject)}">Open</a></article>` +
      `<article class="settings-card"><span class="settings-icon">⌘</span><div><strong>Keys & signers</strong>` +
      `<p>Social holds no signing material. ${model.publicWrite.signerState === "connected" ? "The last explicit external-signer check matched this session; every action rechecks." : "No external signer has matched this page session."}</p></div>${model.publicWrite.signerState === "connected" ? "<span>Matched</span>" : "<span>Protected</span>"}</article>` +
      `<article class="settings-card"><span class="settings-icon">◉</span><div><strong>Relay settings</strong>` +
      `<p>${escapeHtml(model.publicRead.relayHost ? `One bounded browser read from ${model.publicRead.relayHost}. ${model.publicWrite.relayHost ? `Explicit publications target ${model.publicWrite.relayHost}.` : "No publish relay is configured."}` : "No public read relay is currently available.")}</p></div><span>${model.publicWrite.relayHost ? "Explicit publish" : model.publicRead.relayHost ? "Read only" : "Unavailable"}</span></article>` +
      `<article class="settings-card"><span class="settings-icon">◌</span><div><strong>Privacy & discoverability</strong>` +
      `<p>Network visibility preferences are not published yet.</p></div><span>Pending</span></article>` +
      `<article class="settings-card"><span class="settings-icon">⇩</span><div><strong>Export & backup</strong>` +
      `<p>No profile, follow or relay records are stored by this shell.</p></div><span>No data</span></article>` +
      `</div></section>`
  });

export function createAuthenticatedProductModel({
  subject,
  status,
  authorityValid,
  publicRead = DEFAULT_PUBLIC_READ,
  publicWrite = DEFAULT_PUBLIC_WRITE,
  fullDirectory = DEFAULT_FULL_DIRECTORY,
  privateLabels = []
}) {
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject) ||
    !PRODUCT_STATUSES.has(status) ||
    typeof authorityValid !== "boolean"
  ) {
    throw new TypeError("invalid authenticated product model");
  }

  const normalizedFullDirectory =
    normalizeFullDirectory(fullDirectory);

  return Object.freeze({
    subject,
    status,
    authorityValid,
    publicRead: normalizePublicRead(publicRead),
    publicWrite: normalizePublicWrite(publicWrite),
    fullDirectory: normalizedFullDirectory,
    privateLabels: normalizePrivateLabels(
      privateLabels,
      normalizedFullDirectory
    )
  });
}

export function renderAuthenticatedProductPage(route, model) {
  if (!route || typeof route.page !== "string") {
    return renderPageFrame({
      eyebrow: "Navigation",
      title: "Page unavailable",
      content: renderUnavailableState("route")
    });
  }

  if (route.page === "home") return homePage(model);
  if (route.page === "profile") return profilePage(model);
  if (route.page === "circle") return circlePage(model);
  if (route.page === "search") return searchPage(model, route.searchQuery);
  if (route.page === "discover") return directoryPage(model, "Discover", "discover");
  if (route.page === "full-network" && hasFullNetworkAccess(model)) {
    return fullNetworkPage(model);
  }
  if (route.page === "friends") return directoryPage(model, "Friends", "friends");
  if (route.page === "discovery") return directoryPage(model, "Friends of Friends", "discovery");
  if (route.page === "messages") return messagesPage(model);
  if (route.page === "groups") return groupsPage();
  if (route.page === "notifications") return notificationsPage();
  if (route.page === "activity") return activityPage(model);
  if (route.page === "trust") return trustPage(model);
  if (route.page === "settings") return settingsPage(model);

  return renderPageFrame({
    eyebrow: "Navigation",
    title: "Page unavailable",
    content: renderUnavailableState("route")
  });
}

export const renderAuthenticatedProfileContext = (model) =>
  profileHero(model, true);

export const renderAuthenticatedNetworkContext = (model) =>
  `<article class="viewer-card network-context"><p class="eyebrow">Network activity</p>` +
  `<div class="network-context-row"><span>Direct friends</span><strong>0</strong></div>` +
  `<div class="network-context-row"><span>Two-hop reach</span><strong>0</strong></div>` +
  `<div class="network-context-row"><span>Visible posts</span><strong>${escapeHtml(publicPostCount(model))}</strong></div>` +
  `<div class="network-context-row"><span>Groups</span><strong>0</strong></div>` +
  `<p class="notice">Post count reflects only signature-verified kind 1 events for the current session subject. Relationship counts remain unconnected.</p>` +
  `${actionLink("#/circle", "View My Circle", true)}</article>`;
