import {
  escapeHtml,
  renderPageFrame
} from "./components.mjs?v=1.20.0";

import {
  createAuthenticatedProductModel,
  renderAuthenticatedNetworkContext,
  renderAuthenticatedProductPage,
  renderAuthenticatedProfileContext
} from "./auth-product.mjs?v=1.20.0";

import { renderNavigation } from "./shell.mjs?v=1.20.0";

import {
  canonicalNostrRelayUrl,
  createPendingAuthenticatedPublicRead,
  createUnavailableAuthenticatedPublicRead,
  loadAuthenticatedPublicRead
} from "./authenticated-public-read.mjs?v=1.20.0";

import {
  AUTHENTICATED_SIGNER_STATES,
  connectAuthenticatedNip07Signer,
  publishAuthenticatedNote,
  publishAuthenticatedProfile
} from "./authenticated-public-write.mjs?v=1.20.0";

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
  "/trust": "trust",
  "/settings": "settings"
});

const DISABLED_PUBLIC_WRITE = Object.freeze({
  relayHost: null,
  signerState: "disabled",
  operation: "idle"
});

const publicWriteState = (
  relayUrl,
  signerState = "disconnected",
  operation = "idle"
) => Object.freeze({
  relayHost: new URL(relayUrl).host,
  signerState,
  operation
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

export function parseSocialReadConfigDocument(value) {
  if (!plainObject(value)) {
    throw new TypeError("invalid Social public read configuration");
  }

  if (
    value.enabled === false &&
    exactKeys(value, ["enabled"])
  ) {
    return Object.freeze({ enabled: false });
  }

  if (
    value.enabled === true &&
    exactKeys(value, ["enabled", "relayUrl"]) &&
    typeof value.relayUrl === "string"
  ) {
    try {
      const relayUrl = canonicalNostrRelayUrl(value.relayUrl);
      if (relayUrl === value.relayUrl) {
        return Object.freeze({
          enabled: true,
          relayUrl
        });
      }
    } catch {
      // All malformed config documents share one fixed browser diagnostic.
    }
  }

  throw new TypeError("invalid Social public read configuration");
}

export function parseSocialPublishConfigDocument(value) {
  try {
    return parseSocialReadConfigDocument(value);
  } catch {
    throw new TypeError("invalid Social publish configuration");
  }
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

export async function readSocialPublicReadConfig(
  fetchImpl = globalThis.fetch
) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("Social public read configuration unavailable");
  }

  const response = await fetchImpl("/auth/social-read-config", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json"
    }
  });

  return parseSocialReadConfigDocument(
    await decodeJsonResponse(response)
  );
}

export async function readSocialPublishConfig(
  fetchImpl = globalThis.fetch
) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("Social publish configuration unavailable");
  }

  const response = await fetchImpl("/auth/social-publish-config", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json"
    }
  });

  return parseSocialPublishConfigDocument(
    await decodeJsonResponse(response)
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
  const path = (raw.startsWith("#") ? raw.slice(1) : raw)
    .slice(0, 512);

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

  if (path === "/search" || path.startsWith("/search?")) {
    let searchQuery = "";

    try {
      const marker = path.indexOf("?");
      const rawQuery = marker < 0
        ? ""
        : new URLSearchParams(path.slice(marker + 1)).get("q") ?? "";

      searchQuery = rawQuery
        .normalize("NFKC")
        .replace(/[\u0000-\u001f\u007f]/g, "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120);
    } catch {
      searchQuery = "";
    }

    return Object.freeze({
      page: "search",
      path: "/search",
      searchQuery
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

export function buildAuthenticatedProductView(
  session,
  authority,
  hash = "",
  publicRead = createUnavailableAuthenticatedPublicRead(),
  publicWrite = DISABLED_PUBLIC_WRITE
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
  const model = createAuthenticatedProductModel({
    subject: session.subject,
    status,
    authorityValid: checkedAuthority.valid,
    publicRead,
    publicWrite
  });

  return Object.freeze({
    route,
    status,
    page: renderAuthenticatedProductPage(route, model),
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
    profile: renderAuthenticatedProfileContext(model),
    networkContext: renderAuthenticatedNetworkContext(model)
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
    browser = globalThis.window,
    publicReadLoader = loadAuthenticatedPublicRead,
    signerConnector = connectAuthenticatedNip07Signer,
    notePublisher = publishAuthenticatedNote,
    profilePublisher = publishAuthenticatedProfile
  } = {}
) {
  if (
    typeof publicReadLoader !== "function" ||
    typeof signerConnector !== "function" ||
    typeof notePublisher !== "function" ||
    typeof profilePublisher !== "function"
  ) {
    throw new TypeError("authenticated entry unavailable");
  }
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
  const contextNetwork = requiredElement(
    root,
    "#context-network"
  );

  let currentSession = null;
  let currentAuthority = null;
  let currentPublicRead = null;
  let currentReadConfig = Object.freeze({ enabled: false });
  let currentPublishConfig = Object.freeze({ enabled: false });
  let currentPublicWrite = DISABLED_PUBLIC_WRITE;

  const clearProduct = () => {
    desktopNavigation.innerHTML = "";
    mobileNavigation.innerHTML = "";
    contextProfile.innerHTML = "";
    contextNetwork.innerHTML = "";

    root.body?.removeAttribute?.("data-access");
  };

  const renderSignedOut = (unavailable = false) => {
    currentSession = Object.freeze({
      authenticated: false
    });
    currentAuthority = null;
    currentPublicRead = null;
    currentReadConfig = Object.freeze({ enabled: false });
    currentPublishConfig = Object.freeze({ enabled: false });
    currentPublicWrite = DISABLED_PUBLIC_WRITE;

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
    currentPublicRead = createPendingAuthenticatedPublicRead();
    currentReadConfig = Object.freeze({ enabled: false });
    currentPublishConfig = Object.freeze({ enabled: false });
    currentPublicWrite = DISABLED_PUBLIC_WRITE;

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
      browser?.location?.hash ?? "",
      currentPublicRead ?? createUnavailableAuthenticatedPublicRead(),
      currentPublicWrite
    );

    desktopNavigation.innerHTML =
      view.desktopNavigation;

    mobileNavigation.innerHTML =
      view.mobileNavigation;

    appPage.innerHTML = view.page;
    contextProfile.innerHTML = view.profile;
    contextNetwork.innerHTML = view.networkContext;

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

      const publicRead = readSocialPublicReadConfig(fetchImpl)
        .then((config) => {
          currentReadConfig = config;
          return config.enabled
            ? publicReadLoader({
                subject: session.subject,
                relayUrl: config.relayUrl
              })
            : createUnavailableAuthenticatedPublicRead();
        })
        .catch(() => createUnavailableAuthenticatedPublicRead());

      const publishConfig = readSocialPublishConfig(fetchImpl)
        .catch(() => Object.freeze({ enabled: false }));

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

      currentPublishConfig = await publishConfig;
      currentPublicWrite = currentPublishConfig.enabled
        ? publicWriteState(currentPublishConfig.relayUrl)
        : DISABLED_PUBLIC_WRITE;
      paintProduct();

      try {
        currentPublicRead = await publicRead;
        paintProduct();
      } catch {
        currentPublicRead = createUnavailableAuthenticatedPublicRead();
        paintProduct();
      }
      return currentSession;
    })
    .catch(() => {
      renderSignedOut(true);
      return currentSession;
    });

  const externalSignerDependencies = () => ({
    resolveProvider: () => browser?.nostr
  });

  const writeContextCurrent = (session, relayUrl) =>
    currentSession === session &&
    currentPublishConfig.enabled === true &&
    currentPublishConfig.relayUrl === relayUrl;

  const connectSigner = async () => {
    if (
      currentSession?.authenticated !== true ||
      !currentPublishConfig.enabled ||
      currentPublicWrite.signerState === "connecting" ||
      currentPublicWrite.operation.startsWith("publishing-")
    ) {
      return false;
    }

    const session = currentSession;
    const relayUrl = currentPublishConfig.relayUrl;

    currentPublicWrite = publicWriteState(
      relayUrl,
      "connecting"
    );
    paintProduct();

    let result;
    try {
      result = await signerConnector(
        { subject: session.subject },
        externalSignerDependencies()
      );
    } catch {
      result = Object.freeze({
        state: AUTHENTICATED_SIGNER_STATES.unavailable
      });
    }

    if (!writeContextCurrent(session, relayUrl)) {
      return false;
    }

    const signerState = result?.state === AUTHENTICATED_SIGNER_STATES.connected
      ? "connected"
      : result?.state === AUTHENTICATED_SIGNER_STATES.mismatch
        ? "mismatch"
        : "unavailable";

    currentPublicWrite = publicWriteState(
      relayUrl,
      signerState
    );
    paintProduct();
    return signerState === "connected";
  };

  const refreshPublicRead = async () => {
    if (
      currentSession?.authenticated !== true ||
      !currentReadConfig.enabled
    ) {
      return false;
    }

    const previous = currentPublicRead;
    try {
      currentPublicRead = await publicReadLoader({
        subject: currentSession.subject,
        relayUrl: currentReadConfig.relayUrl
      });
      paintProduct();
      return true;
    } catch {
      currentPublicRead = previous;
      paintProduct();
      return false;
    }
  };

  const publish = async (type, fields) => {
    if (
      currentSession?.authenticated !== true ||
      !currentPublishConfig.enabled ||
      currentPublicWrite.signerState !== "connected" ||
      currentPublicWrite.operation.startsWith("publishing-")
    ) {
      return false;
    }

    const session = currentSession;
    const relayUrl = currentPublishConfig.relayUrl;

    currentPublicWrite = publicWriteState(
      relayUrl,
      "connected",
      `publishing-${type}`
    );
    paintProduct();

    const publisher = type === "profile"
      ? profilePublisher
      : notePublisher;

    try {
      await publisher(
        {
          subject: session.subject,
          relayUrl,
          ...fields
        },
        externalSignerDependencies()
      );
      if (!writeContextCurrent(session, relayUrl)) {
        return false;
      }
      currentPublicWrite = publicWriteState(
        relayUrl,
        "connected",
        `published-${type}`
      );
      paintProduct();
      await refreshPublicRead();
      return true;
    } catch {
      if (!writeContextCurrent(session, relayUrl)) {
        return false;
      }
      currentPublicWrite = publicWriteState(
        relayUrl,
        "connected",
        `failed-${type}`
      );
      paintProduct();
      return false;
    }
  };

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

  root.addEventListener?.("click", (event) => {
    if (event.target?.id !== "connect-authenticated-signer") {
      return;
    }
    event.preventDefault?.();
    void connectSigner();
  });

  root.addEventListener?.("submit", (event) => {
    const formId = event.target?.id;
    if (![
      "authenticated-search",
      "authenticated-note-publisher",
      "authenticated-profile-publisher"
    ].includes(formId)) {
      return;
    }

    event.preventDefault?.();

    let fields;
    try {
      fields = new FormData(event.target);
    } catch {
      return;
    }

    if (formId === "authenticated-note-publisher") {
      void publish("note", {
        content: fields.get("content")?.toString() ?? ""
      });
      return;
    }

    if (formId === "authenticated-profile-publisher") {
      void publish("profile", {
        displayName: fields.get("displayName")?.toString() ?? "",
        about: fields.get("about")?.toString() ?? ""
      });
      return;
    }

    const query = fields
      .get("q")
      ?.toString()
      .normalize("NFKC")
      .replace(/[\u0000-\u001f\u007f]/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 120) ?? "";

    if (browser?.location) {
      browser.location.hash = query
        ? `#/search?q=${encodeURIComponent(query)}`
        : "#/search";
    }
  });

  browser?.addEventListener?.("hashchange", () => {
    paintProduct();
  });

  return Object.freeze({
    ready,
    logout,
    connectSigner,
    publishNote: (content) => publish("note", { content }),
    publishProfile: (displayName, about) => publish(
      "profile",
      { displayName, about }
    ),
    repaint: paintProduct,
    currentSession: () => currentSession,
    currentAuthority: () => currentAuthority,
    currentPublicRead: () => currentPublicRead,
    currentPublicWrite: () => currentPublicWrite
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
