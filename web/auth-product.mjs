import {
  escapeHtml,
  renderPageFrame,
  renderStatusBadge,
  renderUnavailableState
} from "./components.mjs";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const PRODUCT_STATUSES = new Set(["limited", "full"]);

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

const membershipStrip = (model) =>
  `<section class="membership-strip" aria-label="Current membership">` +
  `<div class="membership-mark" aria-hidden="true">✓</div>` +
  `<div class="membership-copy"><span>Current membership</span>` +
  `<strong>${escapeHtml(statusLabel(model.status))}</strong>` +
  `<small>${model.authorityValid ? "External authority · checked for this session" : "Fail-closed Limited · authority unavailable"}</small></div>` +
  `${renderStatusBadge(model.status)}` +
  `<a href="#/trust">View details <span aria-hidden="true">→</span></a>` +
  `</section>`;

const readonlyComposer = (model) =>
  `<section class="composer-card authenticated-composer" aria-label="Post composer preview">` +
  `<div class="composer-head"><div class="avatar" aria-hidden="true">H</div>` +
  `<div><strong>Your profile</strong>${renderStatusBadge(model.status)}` +
  `<p>Authenticated as ${escapeHtml(shortKey(model.subject))}</p></div></div>` +
  `<div class="composer-prompt">What’s on your mind?</div>` +
  `<div class="composer-actions"><div class="local-tools" aria-label="Planned post attachments">` +
  `<span>Image</span><span>Poll</span><span>Article</span></div>` +
  `<span class="composer-audience">Audience · Public</span>` +
  `<button type="button" disabled>Post</button></div>` +
  `<p class="notice">Publishing stays unavailable until a signer and write relay are explicitly connected. Nothing is signed or broadcast from this screen.</p>` +
  `</section>`;

const productGuide = (model) =>
  `<article class="post-card product-guide-card">` +
  `<header><div class="avatar product-avatar" aria-hidden="true">H</div>` +
  `<div><strong class="post-author">HODLXXI Social</strong>` +
  `<span class="product-guide-label">Product guide</span>` +
  `<p class="post-meta">Your authenticated workspace · current session</p></div></header>` +
  `<p class="post-body">Your public-key session and ${escapeHtml(statusLabel(model.status))} access are active. Start with your profile, inspect the separate trust context, then build your social circle.</p>` +
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
      readonlyComposer(model) +
      `<div class="feed-toolbar"><div><strong>Home feed</strong><span>Permitted network activity</span></div>` +
      `<div class="feed-filter" aria-label="Feed audience"><span class="active">For you</span><span>Following</span></div></div>` +
      `<section class="feed-stack" aria-label="Home feed">${productGuide(model)}` +
      surfaceEmpty({
        icon: "◎",
        title: "No public network events connected yet",
        detail: "The product shell is active and will show normalized public posts here when the authenticated public-read source is connected.",
        actions:
          actionLink("#/circle", "Open My Circle") +
          actionLink("#/discover", "Discover people", true)
      }) +
      `</section>`
  });

const profileHero = (model, compact = false) =>
  `<article class="authenticated-profile${compact ? " authenticated-profile-compact" : ""}">` +
  `${compact ? "" : '<div class="profile-cover" aria-hidden="true"></div>'}` +
  `<div class="profile-identity"><div class="avatar avatar-large" aria-hidden="true">H</div>` +
  `<div><p class="eyebrow">Authenticated participant</p>` +
  `<h2>Your HODLXXI identity</h2><div class="profile-badges">${renderStatusBadge(model.status)}<span class="session-chip">Session authenticated</span></div></div></div>` +
  `<p class="key">${escapeHtml(model.subject)}</p>` +
  `${compact ? "" : `<p class="profile-lead">This is the only participant identity accepted from the current Social session. Public profile fields will remain separate from membership authority.</p>`}` +
  `<div class="profile-links">` +
  actionLink(`#/profile/${escapeHtml(model.subject)}`, compact ? "Open profile" : "Profile", compact) +
  `${compact ? actionLink("#/trust", "Trust details", true) : ""}</div>` +
  `</article>`;

const profilePage = (model) =>
  renderPageFrame({
    title: "Profile",
    className: "authenticated-profile-page",
    content:
      profileHero(model) +
      `<dl class="profile-stat-row">` +
      `<div><dt>Posts</dt><dd>0</dd></div><div><dt>Friends</dt><dd>0</dd></div><div><dt>Circles</dt><dd>0</dd></div>` +
      `</dl>` +
      `<div class="profile-grid">` +
      `<section class="card"><p class="eyebrow">Public profile</p><h2>Profile details</h2>` +
      `<dl class="detail-list"><div><dt>Display name</dt><dd>Not published</dd></div>` +
      `<div><dt>Bio</dt><dd>Not published</dd></div><div><dt>Public key</dt><dd>${escapeHtml(shortKey(model.subject))}</dd></div></dl>` +
      `<p class="notice">Public presentation data is not inferred from the membership source.</p></section>` +
      `<section class="card"><p class="eyebrow">Membership</p><h2>${escapeHtml(statusLabel(model.status))}</h2>` +
      `<p>${escapeHtml(statusDetail(model))}</p>${actionLink("#/trust", "View trust details")}</section>` +
      `</div>` +
      surfaceEmpty({
        icon: "✦",
        title: "No public posts on this profile",
        detail: "Normalized public posts associated with this authenticated key will appear here after a public-read source is connected."
      })
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

const messagesPage = (model) =>
  renderPageFrame({
    title: "Messages",
    content:
      `<section class="messages-product"><div class="message-tabs"><span class="active">Messages</span><a href="#/groups">Groups</a></div>` +
      `<div class="split-surface authenticated-split"><div class="surface-list"><div class="surface-search">Search conversations</div>` +
      `<div class="surface-list-empty"><span>0</span><p>No conversations</p></div></div>` +
      `<div class="surface-detail">${surfaceEmpty({
        icon: "✉",
        title: "Your inbox is ready",
        detail: "Encrypted conversations will appear here after recipient identity, signer and delivery relays are available. No message transport is active from this screen."
      })}</div></div><p class="notice">Message access never grants membership or sponsor authority.</p></section>`
  });

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
      `<p>${escapeHtml(statusDetail(model))}</p><small>Read-only HODLXXI authority</small></div></article></div>` +
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
      `<p>Social holds no signing material. Signer controls are not connected.</p></div><span>Protected</span></article>` +
      `<article class="settings-card"><span class="settings-icon">◉</span><div><strong>Relay settings</strong>` +
      `<p>No automatic read, write or message relay is selected.</p></div><span>Not configured</span></article>` +
      `<article class="settings-card"><span class="settings-icon">◌</span><div><strong>Privacy & discoverability</strong>` +
      `<p>Network visibility preferences are not published yet.</p></div><span>Pending</span></article>` +
      `<article class="settings-card"><span class="settings-icon">⇩</span><div><strong>Export & backup</strong>` +
      `<p>No profile, follow or relay records are stored by this shell.</p></div><span>No data</span></article>` +
      `</div></section>`
  });

export function createAuthenticatedProductModel({
  subject,
  status,
  authorityValid
}) {
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject) ||
    !PRODUCT_STATUSES.has(status) ||
    typeof authorityValid !== "boolean"
  ) {
    throw new TypeError("invalid authenticated product model");
  }

  return Object.freeze({
    subject,
    status,
    authorityValid
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
  `<div class="network-context-row"><span>Visible posts</span><strong>0</strong></div>` +
  `<div class="network-context-row"><span>Groups</span><strong>0</strong></div>` +
  `<p class="notice">Counts reflect only the authenticated dataset currently connected to this session.</p>` +
  `${actionLink("#/circle", "View My Circle", true)}</article>`;
