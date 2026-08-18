import {
  escapeHtml,
  renderPageFrame,
  renderStatusBadge,
  renderUnavailableState
} from "./components.mjs";

import { renderNavigation } from "./shell.mjs";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const MAX_JSON_BODY_BYTES = 1024;

const PRODUCT_ROUTES = Object.freeze({
  "/home": "home",
  "/circle": "circle",
  "/search": "search",
  "/discover": "discover",
  "/friends": "friends",
  "/friends-of-friends": "discovery",
  "/messages": "messages",
  "/groups": "groups",
  "/notifications": "notifications",
  "/activity": "activity",
  "/trust": "trust"
});

const PRODUCT_TITLES = Object.freeze({
  home: "Home",
  circle: "My Circle",
  search: "Search",
  discover: "Discover",
  friends: "Friends",
  discovery: "Friends of Friends",
  messages: "Messages",
  groups: "Groups",
  notifications: "Notifications",
  activity: "Activity",
  profile: "Profile",
  trust: "Trust"
});

const exactKeys = (value, expected) => {
  const keys = Object.keys(value).sort();

  return (
    keys.length === expected.length &&
    expected.every((name, index) => keys[index] === name)
  );
};

const plainObject = (value) =>
  Boolean(value) &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const failClosedAuthority = (subject) =>
  Object.freeze({
    subject,
    status: "limited",
    valid: false
  });

const shortKey = (subject) =>
  `${subject.slice(0, 8)}…${subject.slice(-6)}`;

async function decodeJsonResponse(response) {
  if (
    !response ||
    response.status !== 200 ||
    typeof response.text !== "function" ||
    typeof response.headers?.get !== "function"
  ) {
    throw new TypeError("Social read unavailable");
  }

  const contentType = response.headers.get("content-type");

  if (
    typeof contentType !== "string" ||
    contentType.split(";", 1)[0].trim().toLowerCase() !==
      "application/json"
  ) {
    throw new TypeError("Social read unavailable");
  }

  const body = await response.text();

  if (
    body.length === 0 ||
    new TextEncoder().encode(body).byteLength > MAX_JSON_BODY_BYTES
  ) {
    throw new TypeError("Social read unavailable");
  }

  try {
    return JSON.parse(body);
  } catch {
    throw new TypeError("Social read unavailable");
  }
}

export function parseSessionDocument(value) {
  if (!plainObject(value)) {
    throw new TypeError("invalid Social session");
  }

  if (
    value.authenticated === false &&
    exactKeys(value, ["authenticated"])
  ) {
    return Object.freeze({ authenticated: false });
  }

  if (
    value.authenticated === true &&
    exactKeys(value, ["authenticated", "subject"]) &&
    typeof value.subject === "string" &&
    CANONICAL_SUBJECT.test(value.subject)
  ) {
    return Object.freeze({
      authenticated: true,
      subject: value.subject
    });
  }

  throw new TypeError("invalid Social session");
}

export function parseAuthorityDocument(value, expectedSubject) {
  if (
    !plainObject(value) ||
    typeof expectedSubject !== "string" ||
    !CANONICAL_SUBJECT.test(expectedSubject) ||
    !exactKeys(value, ["status", "subject", "valid"]) ||
    value.subject !== expectedSubject ||
    typeof value.status !== "string" ||
    typeof value.valid !== "boolean"
  ) {
    throw new TypeError("invalid Social authority");
  }

  if (
    value.valid === true &&
    ["limited", "full"].includes(value.status)
  ) {
    return Object.freeze({
      subject: expectedSubject,
      status: value.status,
      valid: true
    });
  }

  if (
    value.valid === false &&
    value.status === "limited"
  ) {
    return failClosedAuthority(expectedSubject);
  }

  throw new TypeError("invalid Social authority");
}

export async function readSocialSession(fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("Social session unavailable");
  }

  const response = await fetchImpl("/auth/session", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json"
    }
  });

  return parseSessionDocument(await decodeJsonResponse(response));
}

export async function readSocialAuthority(
  expectedSubject,
  fetchImpl = globalThis.fetch
) {
  if (
    typeof fetchImpl !== "function" ||
    typeof expectedSubject !== "string" ||
    !CANONICAL_SUBJECT.test(expectedSubject)
  ) {
    throw new TypeError("Social authority unavailable");
  }

  const response = await fetchImpl("/auth/authority", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json"
    }
  });

  return parseAuthorityDocument(
    await decodeJsonResponse(response),
    expectedSubject
  );
}

export async function logoutSocialSession(
  fetchImpl = globalThis.fetch
) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("Social logout unavailable");
  }

  const response = await fetchImpl("/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json"
    }
  });

  const session = parseSessionDocument(
    await decodeJsonResponse(response)
  );

  if (session.authenticated !== false) {
    throw new TypeError("Social logout unavailable");
  }

  return session;
}

export function parseAuthenticatedRoute(hash, subject) {
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject)
  ) {
    return Object.freeze({
      page: "not-found",
      path: "/not-found"
    });
  }

  const raw = typeof hash === "string" ? hash : "";
  const path = raw.startsWith("#") ? raw.slice(1) : raw;

  if (path === "" || path === "/") {
    return Object.freeze({
      page: "home",
      path: "/home"
    });
  }

  if (path === `/profile/${subject}`) {
    return Object.freeze({
      page: "profile",
      path,
      subjectId: subject
    });
  }

  if (path.startsWith("/profile/")) {
    return Object.freeze({
      page: "not-found",
      path: "/not-found"
    });
  }

  const page = PRODUCT_ROUTES[path];

  return page
    ? Object.freeze({ page, path })
    : Object.freeze({
        page: "not-found",
        path: "/not-found"
      });
}

const productStatus = (authority) =>
  authority?.valid === true &&
  ["limited", "full"].includes(authority.status)
    ? authority.status
    : "limited";

const participantCard = (subject, status) =>
  `<article class="profile-card">` +
  `<div class="avatar avatar-large" aria-hidden="true">H</div>` +
  `<h2>Authenticated participant</h2>` +
  `${renderStatusBadge(status)}` +
  `<p class="key">${escapeHtml(subject)}</p>` +
  `<p class="notice">` +
  `This public key comes only from the authenticated Social session. ` +
  `The access badge is projected only from current external HODLXXI authority.` +
  `</p>` +
  `</article>`;

const productHome = (subject, status, valid) =>
  `<article class="card">` +
  `<p class="eyebrow">Authenticated product</p>` +
  `<h2>Welcome to HODLXXI Social</h2>` +
  `<p class="key">${escapeHtml(subject)}</p>` +
  `${renderStatusBadge(status)}` +
  `<p>` +
  `Your Social viewer is bound to this authenticated public key. ` +
  `No demo identity can replace it.` +
  `</p>` +
  `<p class="notice">` +
  `${
    valid
      ? "Current Limited/Full access was accepted from external HODLXXI authority."
      : "External Full authority was not accepted, so Social is operating as Limited."
  }` +
  `</p>` +
  `</article>`;

const productTrust = (subject, status, valid) =>
  `<article class="card trust-copy">` +
  `<p><strong>${escapeHtml(status)} access</strong> · read-only external assertion</p>` +
  `<p class="key">${escapeHtml(subject)}</p>` +
  `<p>` +
  `${
    valid
      ? "The current access projection was accepted from the HODLXXI authority boundary."
      : "The authority boundary failed closed to Limited."
  }` +
  `</p>` +
  `<p>` +
  `Social does not issue or upgrade covenant status. Friendship does not prove covenant trust. ` +
  `No trust score is calculated.` +
  `</p>` +
  `</article>`;

const unconnectedSurface = (page) =>
  `<article class="ui-state ui-state-empty">` +
  `<div>` +
  `<strong>${escapeHtml(PRODUCT_TITLES[page] ?? "Surface")} ready</strong>` +
  `<p class="meta">` +
  `No authenticated social dataset is connected to this surface in V1.14. ` +
  `No synthetic fallback is used.` +
  `</p>` +
  `</div>` +
  `</article>`;

export function buildAuthenticatedProductView(
  session,
  authority,
  hash = ""
) {
  if (
    !session ||
    session.authenticated !== true ||
    typeof session.subject !== "string" ||
    !CANONICAL_SUBJECT.test(session.subject)
  ) {
    throw new TypeError("authenticated session required");
  }

  const checkedAuthority = parseAuthorityDocument(
    authority,
    session.subject
  );

  const status = productStatus(checkedAuthority);
  const route = parseAuthenticatedRoute(
    hash,
    session.subject
  );

  let content;

  if (route.page === "home") {
    content = productHome(
      session.subject,
      status,
      checkedAuthority.valid
    );
  } else if (route.page === "profile") {
    content = participantCard(session.subject, status);
  } else if (route.page === "trust") {
    content = productTrust(
      session.subject,
      status,
      checkedAuthority.valid
    );
  } else if (Object.hasOwn(PRODUCT_TITLES, route.page)) {
    content = unconnectedSurface(route.page);
  } else {
    content = renderUnavailableState("route");
  }

  const page = renderPageFrame({
    title:
      PRODUCT_TITLES[route.page] ??
      "Page unavailable",
    content
  });

  return Object.freeze({
    route,
    status,
    page,
    desktopNavigation: renderNavigation(
      route,
      session.subject,
      "nav-links",
      0
    ),
    mobileNavigation: renderNavigation(
      route,
      session.subject,
      "mobile-nav",
      0
    ),
    profile: participantCard(session.subject, status)
  });
}

const requiredElement = (root, selector) => {
  const element = root?.querySelector?.(selector);

  if (!element) {
    throw new TypeError("authenticated entry unavailable");
  }

  return element;
};

export function bindAuthenticatedEntry(
  root,
  {
    fetchImpl = globalThis.fetch,
    browser = globalThis.window
  } = {}
) {
  const sessionPrincipal = requiredElement(
    root,
    "#session-principal"
  );
  const sessionDetail = requiredElement(
    root,
    "#session-detail"
  );
  const signIn = requiredElement(root, "#sign-in");
  const signOut = requiredElement(root, "#sign-out");
  const indicator = requiredElement(
    root,
    "#session-indicator-text"
  );
  const authorityStatus = requiredElement(
    root,
    "#authority-status"
  );
  const authoritySummary = requiredElement(
    root,
    "#authority-summary"
  );
  const desktopNavigation = requiredElement(
    root,
    "#desktop-navigation"
  );
  const mobileNavigation = requiredElement(
    root,
    "#mobile-navigation"
  );
  const appPage = requiredElement(root, "#app-page");
  const contextProfile = requiredElement(
    root,
    "#context-profile"
  );

  let currentSession = null;
  let currentAuthority = null;

  const clearProduct = () => {
    desktopNavigation.innerHTML = "";
    mobileNavigation.innerHTML = "";
    contextProfile.innerHTML = "";

    root.body?.removeAttribute?.("data-access");
  };

  const renderSignedOut = (unavailable = false) => {
    currentSession = Object.freeze({
      authenticated: false
    });
    currentAuthority = null;

    clearProduct();

    sessionPrincipal.textContent = unavailable
      ? "Session unavailable"
      : "Signed out";

    sessionDetail.textContent = unavailable
      ? "No authenticated subject was accepted. Start a new HODLXXI sign-in."
      : "Sign in with a HODLXXI public-key identity.";

    signIn.hidden = false;
    signOut.hidden = true;
    signOut.disabled = false;

    indicator.textContent = "Signed out";

    authorityStatus.textContent = "Not available";
    authoritySummary.textContent =
      "External authority is not read without an authenticated Social subject.";

    appPage.innerHTML = renderPageFrame({
      title: "Sign in",
      content:
        `<article class="card">` +
        `<h2>HODLXXI public-key entry</h2>` +
        `<p>No email, phone number, password, or synthetic viewer is used.</p>` +
        `</article>`
    });
  };

  const renderPendingAuthority = (session) => {
    currentSession = session;
    currentAuthority = null;

    clearProduct();

    sessionPrincipal.textContent =
      shortKey(session.subject);

    sessionDetail.textContent =
      "Canonical authenticated public-key subject.";

    signIn.hidden = true;
    signOut.hidden = false;
    signOut.disabled = false;

    indicator.textContent = "Authenticated";

    authorityStatus.textContent =
      "Checking HODLXXI authority";

    authoritySummary.textContent =
      "Reading the external Limited/Full assertion for this exact session subject.";

    appPage.innerHTML = renderPageFrame({
      title: "Checking access",
      content:
        `<article class="card">` +
        `<p class="key">${escapeHtml(session.subject)}</p>` +
        `<p>Authentication is established. Authority is still being checked.</p>` +
        `</article>`
    });
  };

  const paintProduct = () => {
    if (
      currentSession?.authenticated !== true ||
      !currentAuthority
    ) {
      return;
    }

    const view = buildAuthenticatedProductView(
      currentSession,
      currentAuthority,
      browser?.location?.hash ?? ""
    );

    desktopNavigation.innerHTML =
      view.desktopNavigation;

    mobileNavigation.innerHTML =
      view.mobileNavigation;

    appPage.innerHTML = view.page;
    contextProfile.innerHTML = view.profile;

    authorityStatus.textContent =
      view.status === "full" ? "Full" : "Limited";

    authoritySummary.textContent =
      currentAuthority.valid
        ? "Access is projected from the current external HODLXXI authority assertion."
        : "External Full authority was not accepted. Social fails closed to Limited.";

    root.body?.setAttribute?.(
      "data-access",
      view.status
    );
  };

  const renderAuthority = (authority) => {
    currentAuthority = authority;
    paintProduct();
  };

  const ready = readSocialSession(fetchImpl)
    .then(async (session) => {
      if (!session.authenticated) {
        renderSignedOut(false);
        return currentSession;
      }

      renderPendingAuthority(session);

      let authority;

      try {
        authority = await readSocialAuthority(
          session.subject,
          fetchImpl
        );
      } catch {
        authority = failClosedAuthority(
          session.subject
        );
      }

      renderAuthority(authority);
      return currentSession;
    })
    .catch(() => {
      renderSignedOut(true);
      return currentSession;
    });

  const logout = async () => {
    if (currentSession?.authenticated !== true) {
      renderSignedOut(false);
      return true;
    }

    signOut.disabled = true;
    indicator.textContent = "Signing out";

    try {
      await logoutSocialSession(fetchImpl);

      try {
        browser?.history?.replaceState?.(
          null,
          "",
          "/"
        );
      } catch {
        // URL cleanup is best effort; identity state is still cleared below.
      }

      if (browser?.location) {
        try {
          browser.location.hash = "";
        } catch {
          // Browser location may be read-only in non-browser test doubles.
        }
      }

      renderSignedOut(false);
      return true;
    } catch {
      signOut.disabled = false;
      indicator.textContent = "Authenticated";
      sessionDetail.textContent =
        "Sign out was not completed. The authenticated session remains active.";
      return false;
    }
  };

  signOut.addEventListener?.("click", () => {
    void logout();
  });

  browser?.addEventListener?.("hashchange", () => {
    paintProduct();
  });

  return Object.freeze({
    ready,
    logout,
    repaint: paintProduct,
    currentSession: () => currentSession,
    currentAuthority: () => currentAuthority
  });
}

export function bootstrapAuthenticatedEntry(
  root = globalThis.document,
  fetchImpl = globalThis.fetch,
  browser = globalThis.window
) {
  if (
    !root?.documentElement?.hasAttribute?.(
      "data-hodlxxi-authenticated-entry"
    )
  ) {
    return false;
  }

  bindAuthenticatedEntry(root, {
    fetchImpl,
    browser
  });

  return true;
}

if (typeof document !== "undefined") {
  bootstrapAuthenticatedEntry(
    document,
    globalThis.fetch,
    globalThis.window
  );
}
