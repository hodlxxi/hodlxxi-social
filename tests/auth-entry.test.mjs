import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  bindAuthenticatedEntry,
  buildAuthenticatedProductView,
  logoutSocialSession,
  parseAuthenticatedRoute,
  parseAuthorityDocument,
  parseSocialReadConfigDocument,
  parseSessionDocument,
  readSocialAuthority,
  readSocialPublicReadConfig,
  readSocialSession
} from "../web/auth-entry.mjs";

const subject = "c".repeat(64);
const livePublicRead = () => ({
  relayHost: "relay.example",
  profileState: "available",
  profile: {
    displayName: "Ada <Social>",
    about: "Signed public profile",
    eventId: "1".repeat(64),
    createdAt: "2026-08-23T00:00:00.000Z"
  },
  notesState: "available",
  notes: [{
    id: "2".repeat(64),
    body: "Signed <public> post",
    createdAt: "2026-08-23T00:01:00.000Z"
  }]
});

const response = (
  payload,
  {
    status = 200,
    contentType = "application/json; charset=utf-8"
  } = {}
) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": contentType
    }
  });

class Element {
  constructor() {
    this.textContent = "";
    this.innerHTML = "";
    this.hidden = false;
    this.disabled = false;
    this.listeners = new Map();
  }

  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }
}

function fakeDocument() {
  const elements = Object.fromEntries(
    [
      "#session-principal",
      "#session-detail",
      "#sign-in",
      "#sign-out",
      "#session-indicator-text",
      "#authority-status",
      "#authority-summary",
      "#desktop-navigation",
      "#mobile-navigation",
      "#app-page",
      "#context-profile",
      "#context-network"
    ].map((selector) => [
      selector,
      new Element()
    ])
  );

  const attributes = new Map();
  const listeners = new Map();

  return {
    elements,
    listeners,
    body: {
      setAttribute(name, value) {
        attributes.set(name, value);
      },
      removeAttribute(name) {
        attributes.delete(name);
      },
      getAttribute(name) {
        return attributes.get(name);
      }
    },
    documentElement: {
      hasAttribute(name) {
        return (
          name ===
          "data-hodlxxi-authenticated-entry"
        );
      }
    },
    querySelector(selector) {
      return elements[selector];
    },
    addEventListener(name, callback) {
      listeners.set(name, callback);
    }
  };
}

function fakeBrowser(hash = "#/home") {
  const listeners = new Map();
  const replacements = [];

  return {
    listeners,
    replacements,
    location: {
      hash
    },
    history: {
      replaceState(...args) {
        replacements.push(args);
      }
    },
    addEventListener(name, callback) {
      listeners.set(name, callback);
    }
  };
}

test("session document accepts only exact signed-out or canonical signed-in shapes", () => {
  assert.deepEqual(
    parseSessionDocument({
      authenticated: false
    }),
    {
      authenticated: false
    }
  );

  assert.deepEqual(
    parseSessionDocument({
      authenticated: true,
      subject
    }),
    {
      authenticated: true,
      subject
    }
  );

  for (const malformed of [
    null,
    [],
    {},
    { authenticated: true },
    {
      authenticated: true,
      subject: subject.toUpperCase()
    },
    {
      authenticated: true,
      subject,
      role: "full"
    },
    {
      authenticated: false,
      subject
    }
  ]) {
    assert.throws(
      () => parseSessionDocument(malformed),
      /invalid Social session/
    );
  }
});

test("authority permits exact Limited or Full for the session subject only", () => {
  for (const status of ["limited", "full"]) {
    assert.deepEqual(
      parseAuthorityDocument(
        {
          subject,
          status,
          valid: true
        },
        subject
      ),
      {
        subject,
        status,
        valid: true
      }
    );
  }

  assert.deepEqual(
    parseAuthorityDocument(
      {
        subject,
        status: "limited",
        valid: false
      },
      subject
    ),
    {
      subject,
      status: "limited",
      valid: false
    }
  );

  for (const malformed of [
    {
      subject,
      status: "operator",
      valid: true
    },
    {
      subject: "d".repeat(64),
      status: "full",
      valid: true
    },
    {
      subject,
      status: "full",
      valid: false
    },
    {
      subject,
      status: "full",
      valid: true,
      extra: "elevate"
    }
  ]) {
    assert.throws(
      () =>
        parseAuthorityDocument(
          malformed,
          subject
        ),
      /invalid Social authority/
    );
  }
});

test("public read config accepts only exact disabled or canonical explicit relay documents", () => {
  assert.deepEqual(parseSocialReadConfigDocument({ enabled: false }), {
    enabled: false
  });
  assert.deepEqual(parseSocialReadConfigDocument({
    enabled: true,
    relayUrl: "wss://relay.example/"
  }), {
    enabled: true,
    relayUrl: "wss://relay.example/"
  });

  for (const malformed of [
    { enabled: true, relayUrl: "wss://relay.example" },
    { enabled: true, relayUrl: "ws://relay.example/" },
    { enabled: true },
    { enabled: false, relayUrl: "wss://relay.example/" },
    { enabled: true, relayUrl: "wss://relay.example/", subject }
  ]) {
    assert.throws(
      () => parseSocialReadConfigDocument(malformed),
      /invalid Social public read configuration/
    );
  }
});

test("session authority and logout use exact same-origin endpoints", async () => {
  const calls = [];

  const fetchImpl = async (url, options) => {
    calls.push([url, options]);

    if (url === "/auth/session") {
      return response({
        authenticated: true,
        subject
      });
    }

    if (url === "/auth/authority") {
      return response({
        subject,
        status: "full",
        valid: true
      });
    }

    if (url === "/auth/social-read-config") {
      return response({
        enabled: true,
        relayUrl: "wss://relay.example/"
      });
    }

    assert.equal(url, "/auth/logout");

    return response({
      authenticated: false
    });
  };

  await readSocialSession(fetchImpl);
  await readSocialAuthority(
    subject,
    fetchImpl
  );
  await readSocialPublicReadConfig(fetchImpl);
  await logoutSocialSession(fetchImpl);

  assert.deepEqual(
    calls.map(([url]) => url),
    [
      "/auth/session",
      "/auth/authority",
      "/auth/social-read-config",
      "/auth/logout"
    ]
  );

  for (const [url, options] of calls) {
    assert.equal(
      options.credentials,
      "same-origin",
      url
    );
    assert.equal(
      options.cache,
      "no-store",
      url
    );
    assert.equal(
      options.redirect,
      "error",
      url
    );
  }

  assert.equal(
    calls[3][1].method,
    "POST"
  );

  assert.equal(
    Object.hasOwn(
      calls[3][1].headers,
      "Origin"
    ),
    false
  );
});

test("product view reuses the existing navigation and component classes", () => {
  const view =
    buildAuthenticatedProductView(
      {
        authenticated: true,
        subject
      },
      {
        subject,
        status: "full",
        valid: true
      },
      "#/home"
    );

  assert.equal(view.status, "full");
  assert.equal(view.route.page, "home");

  assert.match(
    view.desktopNavigation,
    /class="nav-links"/
  );

  assert.match(
    view.mobileNavigation,
    /class="mobile-nav"/
  );

  assert.match(
    view.page,
    /class="page(?:\s|\")/
  );

  assert.match(
    view.page,
    /badge-full/
  );

  assert.match(
    view.page,
    new RegExp(subject)
  );

  assert.doesNotMatch(
    view.page +
      view.desktopNavigation +
      view.mobileNavigation,
    /viewer-select|synthetic participant|Operator/
  );
});

test("authenticated routing permits only the current subject profile", () => {
  assert.deepEqual(
    parseAuthenticatedRoute(
      "#/profile/" + subject,
      subject
    ),
    {
      page: "profile",
      path: "/profile/" + subject,
      subjectId: subject
    }
  );

  const other = "d".repeat(64);

  assert.equal(
    parseAuthenticatedRoute(
      "#/profile/" + other,
      subject
    ).page,
    "not-found"
  );

  assert.equal(
    parseAuthenticatedRoute(
      "#/home",
      subject
    ).page,
    "home"
  );

  assert.equal(
    parseAuthenticatedRoute(
      "#/trust",
      subject
    ).page,
    "trust"
  );

  assert.equal(
    parseAuthenticatedRoute(
      "#/settings",
      subject
    ).page,
    "settings"
  );

  assert.deepEqual(
    parseAuthenticatedRoute(
      "#/search?q=you",
      subject
    ),
    {
      page: "search",
      path: "/search",
      searchQuery: "you"
    }
  );
});

test("authenticated routes render complete truthful product surfaces instead of legacy placeholders", () => {
  const routes = new Map([
    ["#/home", /membership-strip/],
    ["#/circle", /auth-circle-title/],
    ["#/search?q=you", /1 permitted result/],
    ["#/discover", /directory-product/],
    ["#/friends", /No direct friends yet/],
    ["#/friends-of-friends", /friends of friends/i],
    ["#/messages", /authenticated-split/],
    ["#/groups", /product-metrics/],
    ["#/notifications", /all caught up/i],
    ["#/activity", /Social session authenticated/],
    [`#/profile/${subject}`, /profile-cover/],
    ["#/trust", /trust-hero/],
    ["#/settings", /settings-grid/]
  ]);

  for (const [hash, expected] of routes) {
    const view = buildAuthenticatedProductView(
      {
        authenticated: true,
        subject
      },
      {
        subject,
        status: "full",
        valid: true
      },
      hash
    );

    assert.match(view.page, expected, hash);
    assert.doesNotMatch(
      view.page,
      /No authenticated social dataset|Synthetic fixture|synthetic demo/i,
      hash
    );
  }
});

test("Home presents membership context, product guidance, and no invented network activity", () => {
  const view = buildAuthenticatedProductView(
    {
      authenticated: true,
      subject
    },
    {
      subject,
      status: "full",
      valid: true
    },
    "#/home"
  );

  assert.match(view.page, /Full Member/);
  assert.match(view.page, /Product guide/);
  assert.match(view.page, /Public posts unavailable/);
  assert.match(view.page, /Publishing stays unavailable/);
  assert.doesNotMatch(view.page, /Ada|Ben|Cy|Dia|reactions|reposts/i);
  assert.match(view.networkContext, /Direct friends<\/span><strong>0/);
});

test("verified own profile and posts render on Home and Profile without affecting authority", () => {
  for (const hash of ["#/home", `#/profile/${subject}`]) {
    const view = buildAuthenticatedProductView(
      { authenticated: true, subject },
      { subject, status: "full", valid: true },
      hash,
      livePublicRead()
    );

    assert.equal(view.status, "full");
    assert.match(view.page, /Ada &lt;Social&gt;/);
    assert.match(view.page, /Signed &lt;public&gt; post/);
    assert.match(view.page, /relay\.example/);
    assert.match(view.page, /signature checked|verified Nostr event/i);
    assert.doesNotMatch(view.page, /<Social>|<public>/);
  }
});

test("malformed public read state cannot enter the authenticated product model", () => {
  for (const publicRead of [
    { ...livePublicRead(), relayHost: "bad relay" },
    { ...livePublicRead(), notesState: "unavailable" },
    { ...livePublicRead(), notes: [{ ...livePublicRead().notes[0], authorId: subject }] },
    { ...livePublicRead(), profile: { ...livePublicRead().profile, eventId: "x".repeat(64) } },
    { ...livePublicRead(), profile: { ...livePublicRead().profile, role: "operator" } },
    { ...livePublicRead(), profileState: "empty" }
  ]) {
    assert.throws(
      () => buildAuthenticatedProductView(
        { authenticated: true, subject },
        { subject, status: "full", valid: true },
        "#/home",
        publicRead
      ),
      /invalid authenticated public read/
    );
  }
});

test("authenticated entry binds relay reads only to the current session subject", async () => {
  const document = fakeDocument();
  const seen = [];
  const binding = bindAuthenticatedEntry(document, {
    browser: fakeBrowser("#/home"),
    fetchImpl: async (url) => {
      if (url === "/auth/session") {
        return response({ authenticated: true, subject });
      }
      if (url === "/auth/authority") {
        return response({ subject, status: "full", valid: true });
      }
      assert.equal(url, "/auth/social-read-config");
      return response({
        enabled: true,
        relayUrl: "wss://relay.example/"
      });
    },
    publicReadLoader: async (input) => {
      seen.push(input);
      return livePublicRead();
    }
  });

  await binding.ready;
  assert.deepEqual(seen, [{
    subject,
    relayUrl: "wss://relay.example/"
  }]);
  assert.deepEqual(binding.currentPublicRead(), livePublicRead());
  assert.match(document.elements["#app-page"].innerHTML, /Ada &lt;Social&gt;/);
  assert.equal(binding.currentAuthority().status, "full");
});

test("malformed live-read output fails closed without signing out or changing authority", async () => {
  const document = fakeDocument();
  const binding = bindAuthenticatedEntry(document, {
    browser: fakeBrowser("#/home"),
    fetchImpl: async (url) => {
      if (url === "/auth/session") return response({ authenticated: true, subject });
      if (url === "/auth/authority") return response({ subject, status: "full", valid: true });
      return response({ enabled: true, relayUrl: "wss://relay.example/" });
    },
    publicReadLoader: async () => ({ operator: true })
  });

  await binding.ready;
  assert.equal(binding.currentSession().subject, subject);
  assert.equal(binding.currentAuthority().status, "full");
  assert.equal(binding.currentPublicRead().notesState, "unavailable");
  assert.match(document.elements["#app-page"].innerHTML, /Public posts unavailable/);
  assert.equal(document.body.getAttribute("data-access"), "full");
});

test("signed-out bootstrap performs no authority read and no product navigation", async () => {
  const document = fakeDocument();
  const browser = fakeBrowser();
  const calls = [];

  const binding = bindAuthenticatedEntry(
    document,
    {
      browser,
      fetchImpl: async (url) => {
        calls.push(url);
        assert.equal(
          url,
          "/auth/session"
        );

        return response({
          authenticated: false
        });
      }
    }
  );

  await binding.ready;

  assert.deepEqual(calls, [
    "/auth/session"
  ]);

  assert.deepEqual(
    binding.currentSession(),
    {
      authenticated: false
    }
  );

  assert.equal(
    binding.currentAuthority(),
    null
  );

  assert.equal(
    document.elements[
      "#desktop-navigation"
    ].innerHTML,
    ""
  );

  assert.equal(
    document.elements["#sign-in"].hidden,
    false
  );

  assert.equal(
    document.elements["#sign-out"].hidden,
    true
  );
});

test("authenticated Full becomes the sole product viewer with external Full status", async () => {
  const document = fakeDocument();
  const browser = fakeBrowser("#/home");

  const binding = bindAuthenticatedEntry(
    document,
    {
      browser,
      fetchImpl: async (url) => {
        if (url === "/auth/session") {
          return response({
            authenticated: true,
            subject
          });
        }

        assert.equal(
          url,
          "/auth/authority"
        );

        return response({
          subject,
          status: "full",
          valid: true
        });
      }
    }
  );

  await binding.ready;

  assert.deepEqual(
    binding.currentSession(),
    {
      authenticated: true,
      subject
    }
  );

  assert.deepEqual(
    binding.currentAuthority(),
    {
      subject,
      status: "full",
      valid: true
    }
  );

  assert.match(
    document.elements[
      "#desktop-navigation"
    ].innerHTML,
    /Home/
  );

  assert.match(
    document.elements[
      "#app-page"
    ].innerHTML,
    new RegExp(subject)
  );

  assert.match(
    document.elements[
      "#app-page"
    ].innerHTML,
    /badge-full/
  );

  assert.equal(
    document.body.getAttribute(
      "data-access"
    ),
    "full"
  );

  assert.equal(
    document.elements[
      "#sign-out"
    ].hidden,
    false
  );
});

test("valid Limited remains Limited and invalid authority fails closed to Limited", async () => {
  for (const authority of [
    {
      subject,
      status: "limited",
      valid: true
    },
    {
      subject,
      status: "limited",
      valid: false
    }
  ]) {
    const view =
      buildAuthenticatedProductView(
        {
          authenticated: true,
          subject
        },
        authority,
        "#/trust"
      );

    assert.equal(
      view.status,
      "limited"
    );

    assert.doesNotMatch(
      view.page,
      /operator/i
    );
  }
});

test("hash navigation repaints without changing authenticated viewer", async () => {
  const document = fakeDocument();
  const browser = fakeBrowser("#/home");

  const binding = bindAuthenticatedEntry(
    document,
    {
      browser,
      fetchImpl: async (url) =>
        url === "/auth/session"
          ? response({
              authenticated: true,
              subject
            })
          : response({
              subject,
              status: "limited",
              valid: true
            })
    }
  );

  await binding.ready;

  browser.location.hash = "#/profile/" + subject;
  browser.listeners.get("hashchange")();

  assert.match(
    document.elements[
      "#app-page"
    ].innerHTML,
    /Authenticated participant/
  );

  assert.match(
    document.elements[
      "#app-page"
    ].innerHTML,
    new RegExp(subject)
  );

  assert.equal(
    binding.currentSession().subject,
    subject
  );
});

test("successful logout clears viewer authority navigation profile and subject URL state", async () => {
  const document = fakeDocument();
  const browser = fakeBrowser(
    "#/profile/" + subject
  );

  let loggedOut = false;

  const binding = bindAuthenticatedEntry(
    document,
    {
      browser,
      fetchImpl: async (url) => {
        if (url === "/auth/session") {
          return response({
            authenticated: true,
            subject
          });
        }

        if (url === "/auth/authority") {
          return response({
            subject,
            status: "full",
            valid: true
          });
        }

        assert.equal(
          url,
          "/auth/logout"
        );

        loggedOut = true;

        return response({
          authenticated: false
        });
      }
    }
  );

  await binding.ready;

  assert.equal(
    await binding.logout(),
    true
  );

  assert.equal(loggedOut, true);

  assert.deepEqual(
    binding.currentSession(),
    {
      authenticated: false
    }
  );

  assert.equal(
    binding.currentAuthority(),
    null
  );

  assert.equal(
    document.elements[
      "#desktop-navigation"
    ].innerHTML,
    ""
  );

  assert.equal(
    document.elements[
      "#context-profile"
    ].innerHTML,
    ""
  );

  assert.equal(
    document.elements[
      "#context-network"
    ].innerHTML,
    ""
  );

  assert.doesNotMatch(
    document.elements[
      "#app-page"
    ].innerHTML,
    new RegExp(subject)
  );

  assert.equal(
    document.body.getAttribute(
      "data-access"
    ),
    undefined
  );

  assert.equal(
    browser.location.hash,
    ""
  );

  assert.equal(
    browser.replacements.length,
    1
  );
});

test("logout failure preserves the authenticated viewer and exposes no private error", async () => {
  const document = fakeDocument();
  const browser = fakeBrowser();

  const binding = bindAuthenticatedEntry(
    document,
    {
      browser,
      fetchImpl: async (url) => {
        if (url === "/auth/session") {
          return response({
            authenticated: true,
            subject
          });
        }

        if (url === "/auth/authority") {
          return response({
            subject,
            status: "limited",
            valid: true
          });
        }

        throw new Error(
          "private logout failure"
        );
      }
    }
  );

  await binding.ready;

  assert.equal(
    await binding.logout(),
    false
  );

  assert.equal(
    binding.currentSession().subject,
    subject
  );

  assert.equal(
    binding.currentAuthority().status,
    "limited"
  );

  assert.doesNotMatch(
    document.elements[
      "#session-detail"
    ].textContent,
    /private logout failure/
  );
});

test("normal authenticated entry imports pure product UI but never synthetic app or fixtures", async () => {
  const [html, module] =
    await Promise.all([
      readFile(
        new URL(
          "../web/index.html",
          import.meta.url
        ),
        "utf8"
      ),
      readFile(
        new URL(
          "../web/auth-entry.mjs",
          import.meta.url
        ),
        "utf8"
      )
    ]);

  assert.match(
    module,
    /from "\.\/components\.mjs\?v=1\.19\.0"/
  );

  assert.match(
    module,
    /from "\.\/shell\.mjs\?v=1\.19\.0"/
  );

  assert.match(
    module,
    /from "\.\/auth-product\.mjs\?v=1\.19\.0"/
  );

  assert.match(
    module,
    /from "\.\/authenticated-public-read\.mjs\?v=1\.19\.0"/
  );

  assert.doesNotMatch(
    module,
    /from "\.\/app\.mjs"|fixtures|SyntheticSocialAdapter|getFixtureData|viewer-select|window\.nostr|NIP-07|nip07|localStorage|sessionStorage|indexedDB|document\.cookie|\?subject=|agent\/authority\/current/i
  );

  assert.doesNotMatch(
    html,
    /data-hodlxxi-synthetic-app|viewer-select|src="\.\/app\.mjs"/
  );

  assert.match(
    html,
    /src="\.\/auth-entry\.mjs\?v=1\.19\.0"/
  );

  assert.match(
    html,
    /href="\.\/styles\.css\?v=1\.19\.0"/
  );

  assert.match(
    html,
    /id="desktop-navigation"/
  );

  assert.match(
    html,
    /id="mobile-navigation"/
  );

  assert.match(
    html,
    /id="sign-out"/
  );

  assert.match(
    html,
    /id="context-network"/
  );

  assert.doesNotMatch(
    html,
    /Development surface|Open synthetic demo/
  );
});

test("authenticated browser graph uses one explicit release revision and no unversioned entry asset", async () => {
  const [html, module, product, publicRead] = await Promise.all([
    readFile(
      new URL("../web/index.html", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../web/auth-entry.mjs", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../web/auth-product.mjs", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../web/authenticated-public-read.mjs", import.meta.url),
      "utf8"
    )
  ]);

  const references = [
    ...html.matchAll(/(?:styles\.css|auth-entry\.mjs)\?v=([0-9.]+)/g),
    ...module.matchAll(/(?:components\.mjs|auth-product\.mjs|shell\.mjs|authenticated-public-read\.mjs)\?v=([0-9.]+)/g),
    ...product.matchAll(/components\.mjs\?v=([0-9.]+)/g),
    ...publicRead.matchAll(/nostr-event-verifier\.mjs\?v=([0-9.]+)/g)
  ];

  assert.equal(references.length, 8);
  assert.deepEqual(
    [...new Set(references.map((match) => match[1]))],
    ["1.19.0"]
  );
  assert.doesNotMatch(
    html,
    /href="\.\/styles\.css"|src="\.\/auth-entry\.mjs"/
  );
  assert.doesNotMatch(
    module,
    /from "\.\/(?:components|auth-product|shell|authenticated-public-read)\.mjs"/
  );
  assert.doesNotMatch(product, /from "\.\/components\.mjs"/);
  assert.doesNotMatch(publicRead, /from "\.\/nostr-event-verifier\.mjs"/);
});

test("synthetic product remains isolated in demo.html", async () => {
  const demo = await readFile(
    new URL(
      "../web/demo.html",
      import.meta.url
    ),
    "utf8"
  );

  assert.match(
    demo,
    /data-hodlxxi-synthetic-app/
  );

  assert.match(
    demo,
    /viewer-select/
  );

  assert.match(
    demo,
    /src="\.\/app\.mjs"/
  );

  assert.match(
    demo,
    /This is not a login/
  );
});

test("browser product contract contains no token secret private key or hard-coded Social origin", async () => {
  const [html, module] =
    await Promise.all([
      readFile(
        new URL(
          "../web/index.html",
          import.meta.url
        ),
        "utf8"
      ),
      readFile(
        new URL(
          "../web/auth-entry.mjs",
          import.meta.url
        ),
        "utf8"
      )
    ]);

  assert.doesNotMatch(
    module,
    /client_secret|access_token|refresh_token|code_verifier|private.?key|document\.cookie|localStorage|sessionStorage|indexedDB/i
  );

  assert.doesNotMatch(
    html + module,
    /social\.hodlxxi\.com|hodlxxi\.social/
  );

  assert.doesNotMatch(
    html,
    /type=["']password["']|email input|phone input/i
  );
});
