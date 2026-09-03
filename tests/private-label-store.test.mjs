import test from "node:test";
import assert from "node:assert/strict";
import {
  readFile,
  readdir
} from "node:fs/promises";

import {
  createBrowserPrivateLabelStore,
  createPrivateLabelStore,
  normalizePrivateLabel
} from "../web/private-label-store.mjs";

const SUBJECT_A = "a".repeat(64);
const SUBJECT_B = "b".repeat(64);

const ALIAS_A = "p_KHcJHzAgVKtH830W3gJGIg";
const ALIAS_B = "member~7";

const memoryStorage = () => {
  const values = new Map();

  return {
    getItem(key) {
      return values.has(key)
        ? values.get(key)
        : null;
    },

    setItem(key, value) {
      values.set(
        String(key),
        String(value)
      );
    },

    removeItem(key) {
      values.delete(String(key));
    },

    values
  };
};

test(
  "private labels normalize human text but reject controls and oversized values",
  () => {
    assert.equal(
      normalizePrivateLabel(
        "  Внук   Алексей  "
      ),
      "Внук Алексей"
    );

    assert.equal(
      normalizePrivateLabel(""),
      ""
    );

    assert.throws(
      () =>
        normalizePrivateLabel(
          "bad\u0000label"
        ),
      TypeError
    );

    assert.throws(
      () =>
        normalizePrivateLabel(
          "я".repeat(65)
        ),
      TypeError
    );
  }
);

test(
  "private labels persist only under the exact viewer and opaque alias",
  () => {
    const storage = memoryStorage();
    const store =
      createPrivateLabelStore(storage);

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );

    assert.equal(
      store.write({
        subject: SUBJECT_A,
        alias: ALIAS_A,
        label: "Внук"
      }),
      true
    );

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      "Внук"
    );

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_B
      }),
      null
    );

    assert.equal(
      store.read({
        subject: SUBJECT_B,
        alias: ALIAS_A
      }),
      null
    );
  }
);

test(
  "blank private label removes the existing device-local label",
  () => {
    const storage = memoryStorage();
    const store =
      createPrivateLabelStore(storage);

    assert.equal(
      store.write({
        subject: SUBJECT_A,
        alias: ALIAS_A,
        label: "Брат"
      }),
      true
    );

    assert.equal(
      store.write({
        subject: SUBJECT_A,
        alias: ALIAS_A,
        label: "   "
      }),
      true
    );

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );
  }
);

test(
  "viewer clear deletes that viewer labels without touching another viewer",
  () => {
    const storage = memoryStorage();
    const store =
      createPrivateLabelStore(storage);

    store.write({
      subject: SUBJECT_A,
      alias: ALIAS_A,
      label: "Сестра"
    });

    store.write({
      subject: SUBJECT_B,
      alias: ALIAS_A,
      label: "Friend"
    });

    assert.equal(
      store.clearViewer({
        subject: SUBJECT_A
      }),
      true
    );

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );

    assert.equal(
      store.read({
        subject: SUBJECT_B,
        alias: ALIAS_A
      }),
      "Friend"
    );
  }
);

test(
  "corrupt or attacker-controlled storage fails closed and is never rendered as a label",
  () => {
    const storage = memoryStorage();

    storage.setItem(
      `hodlxxi.social.private-labels.v1.${SUBJECT_A}`,
      JSON.stringify({
        version: 1,
        labels: [
          {
            alias: ALIAS_A,
            label: "ok"
          },
          {
            alias: ALIAS_A,
            label: "duplicate"
          }
        ]
      })
    );

    const store =
      createPrivateLabelStore(storage);

    assert.equal(
      store.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );

    assert.equal(
      store.write({
        subject: SUBJECT_A,
        alias: ALIAS_B,
        label: "Other"
      }),
      false
    );
  }
);

test(
  "unavailable or throwing browser storage degrades to a no-op store",
  () => {
    const unavailable =
      createPrivateLabelStore(null);

    assert.equal(
      unavailable.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );

    assert.equal(
      unavailable.write({
        subject: SUBJECT_A,
        alias: ALIAS_A,
        label: "Family"
      }),
      false
    );

    const browser = {};

    Object.defineProperty(
      browser,
      "localStorage",
      {
        get() {
          throw new Error(
            "storage unavailable"
          );
        }
      }
    );

    const throwing =
      createBrowserPrivateLabelStore(
        browser
      );

    assert.equal(
      throwing.read({
        subject: SUBJECT_A,
        alias: ALIAS_A
      }),
      null
    );
  }
);

test(
  "private-label module is the sole browser persistence boundary and contains no network or authority path",
  async () => {
    const webDirectory = new URL(
      "../web/",
      import.meta.url
    );

    const filenames =
      await readdir(webDirectory);

    const sources = [];

    for (const filename of filenames) {
      if (!filename.endsWith(".mjs")) {
        continue;
      }

      sources.push([
        filename,
        await readFile(
          new URL(
            `../web/${filename}`,
            import.meta.url
          ),
          "utf8"
        )
      ]);
    }

    const labelSource =
      sources.find(
        ([name]) =>
          name ===
          "private-label-store.mjs"
      )?.[1];

    assert.equal(
      typeof labelSource,
      "string"
    );

    assert.match(
      labelSource,
      /localStorage/
    );

    assert.doesNotMatch(
      labelSource,
      /sessionStorage|indexedDB|document\.cookie|cookieStore|fetch\(|XMLHttpRequest|WebSocket|WebTransport|EventSource|\/auth\/|\/internal\/|private.?key|nsec|xprv|grantFull|issueCRT|bitcoin|lightning|NIP-0?4|NIP-44/i
    );

    for (const [name, source] of sources) {
      if (
        name ===
        "private-label-store.mjs"
      ) {
        continue;
      }

      assert.doesNotMatch(
        source,
        /localStorage/,
        `${name} must not own browser persistence`
      );
    }
  }
);
