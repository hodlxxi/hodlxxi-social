import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  bindAuthenticatedEntry,
  buildAuthenticatedProductView,
  logoutSocialSession,
  parseAuthenticatedRoute,
  parseAuthorityDocument,
  parseSessionDocument,
  readSocialAuthority,
  readSocialSession
} from "../web/auth-entry.mjs";

const subject = "c".repeat(64);

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
      "#context-profile"
    ].map((selector) => [
      selector,
      new Element()
    ])
  );

  const attributes = new Map();

  return {
    elements,
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
  await logoutSocialSession(fetchImpl);

  assert.deepEqual(
    calls.map(([url]) => url),
    [
      "/auth/session",
      "/auth/authority",
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
    calls[2][1].method,
    "POST"
  );

  assert.equal(
    Object.hasOwn(
      calls[2][1].headers,
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
    /class="page"/
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
    /from "\.\/components\.mjs"/
  );

  assert.match(
    module,
    /from "\.\/shell\.mjs"/
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
    /src="\.\/auth-entry\.mjs"/
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
