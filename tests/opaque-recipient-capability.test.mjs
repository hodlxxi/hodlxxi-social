import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEFAULT_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS,
  OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
  OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE,
  createOpaqueRecipientCapabilityStore
} from "../src/server/opaque-recipient-capability.mjs";

const viewerA = "a".repeat(64);
const viewerB = "b".repeat(64);

const sessionA = "A".repeat(43);
const sessionB = "B".repeat(43);

const aliasA =
  "p_KHcJHzAgVKtH830W3gJGIg";

const aliasB =
  "p_o8YlA6r_0WQmPpOfJp4aXA";

const currentAliases = (...aliases) =>
  aliases.map((alias) => ({ alias }));

const deterministicRandom = () =>
  Buffer.alloc(32, 7);

test(
  "issues only an opaque capability for a current accepted alias",
  () => {
    const now = 1_700_000_000_000;

    const store =
      createOpaqueRecipientCapabilityStore({
        random: deterministicRandom
      });

    const result = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA, aliasB),
      now
    });

    assert.equal(
      result.state,
      "available"
    );

    assert.match(
      result.capability,
      /^rc_[A-Za-z0-9_-]{43}$/
    );

    assert.equal(
      result.expiresAt,
      now +
        DEFAULT_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS
    );

    const serialized =
      JSON.stringify(result);

    assert.equal(
      serialized.includes(viewerA),
      false
    );

    assert.equal(
      serialized.includes(sessionA),
      false
    );

    assert.equal(
      serialized.includes(aliasA),
      false
    );

    assert.ok(Object.isFrozen(result));
  }
);

test(
  "resolves only for the same viewer purpose and a still-current alias",
  () => {
    const now = 1_700_000_000_000;
    let seed = 1;

    const store =
      createOpaqueRecipientCapabilityStore({
        random() {
          return Buffer.alloc(
            32,
            seed++
          );
        }
      });

    const issued = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now
    });

    assert.deepEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: now + 1
      }),
      {
        state: "available",
        alias: aliasA
      }
    );

    assert.strictEqual(
      store.resolve({
        subject: viewerB,
      sessionId: sessionB,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: now + 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.strictEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          issued.capability,
        purpose: "full-network-post",
        currentAliases:
          currentAliases(aliasA),
        now: now + 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );
  }
);

test(
  "removed or rotated aliases invalidate an existing capability",
  () => {
    const now = 1_700_000_000_000;

    const store =
      createOpaqueRecipientCapabilityStore({
        random: deterministicRandom
      });

    const issued = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now
    });

    assert.strictEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasB),
        now: now + 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.strictEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases: [],
        now: now + 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );
  }
);

test(
  "expiry fails closed and releases bounded capacity",
  () => {
    const now = 1_700_000_000_000;
    let seed = 1;

    const store =
      createOpaqueRecipientCapabilityStore({
        capacity: 1,
        ttlMs: 10,
        random() {
          return Buffer.alloc(
            32,
            seed++
          );
        }
      });

    const first = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now
    });

    assert.equal(
      first.state,
      "available"
    );

    assert.strictEqual(
      store.issue({
        subject: viewerA,
      sessionId: sessionA,
        alias: aliasB,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasB),
        now: now + 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.strictEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          first.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: now + 10
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    const second = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasB,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasB),
      now: now + 10
    });

    assert.equal(
      second.state,
      "available"
    );
  }
);

test(
  "cannot issue outside the accepted current alias set",
  () => {
    const store =
      createOpaqueRecipientCapabilityStore({
        random: deterministicRandom
      });

    assert.strictEqual(
      store.issue({
        subject: viewerA,
      sessionId: sessionA,
        alias: aliasB,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );
  }
);

test(
  "malformed records accessors duplicates and key-like aliases fail closed",
  () => {
    const store =
      createOpaqueRecipientCapabilityStore({
        random: deterministicRandom
      });

    const getter = {};
    let getterCalls = 0;

    Object.defineProperty(
      getter,
      "alias",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error(
            "must not execute"
          );
        }
      }
    );

    const badAliasLists = [
      [getter],
      [
        { alias: aliasA },
        { alias: aliasA }
      ],
      [{ alias: "a".repeat(64) }],
      [{ alias: "npub1secret" }],
      [{ alias: "xpub-secret" }],
      [{ alias: "someone@example.com" }],
      new Array(1)
    ];

    for (const aliases of badAliasLists) {
      assert.strictEqual(
        store.issue({
          subject: viewerA,
      sessionId: sessionA,
          alias: aliasA,
          purpose:
            OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
          currentAliases: aliases,
          now: 1
        }),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );
    }

    assert.equal(getterCalls, 0);

    assert.strictEqual(
      store.issue({
        subject: viewerA.toUpperCase(),
        alias: aliasA,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 1
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );
  }
);

test(
  "random collisions never overwrite an existing capability",
  () => {
    const store =
      createOpaqueRecipientCapabilityStore({
        random: deterministicRandom,
        capacity: 2
      });

    const first = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now: 1
    });

    assert.equal(
      first.state,
      "available"
    );

    assert.strictEqual(
      store.issue({
        subject: viewerA,
      sessionId: sessionA,
        alias: aliasB,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasB),
        now: 2
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.deepEqual(
      store.resolve({
        subject: viewerA,
      sessionId: sessionA,
        capability:
          first.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 3
      }),
      {
        state: "available",
        alias: aliasA
      }
    );
  }
);

test(
  "capabilities are bound to the exact authenticated server session",
  () => {
    let seed = 1;

    const store =
      createOpaqueRecipientCapabilityStore({
        random() {
          return Buffer.alloc(
            32,
            seed++
          );
        }
      });

    const issued = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now: 1
    });

    assert.equal(
      issued.state,
      "available"
    );

    assert.strictEqual(
      store.resolve({
        subject: viewerA,
        sessionId: sessionB,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 2
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.equal(
      store.resolve({
        subject: viewerA,
        sessionId: sessionA,
        capability:
          issued.capability,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 2
      }).state,
      "available"
    );

    assert.deepEqual(
      Object.keys(store).sort(),
      ["issue", "resolve"]
    );
  }
);

test(
  "per-session quota prevents one authenticated session from exhausting global capacity",
  () => {
    let seed = 1;

    const store =
      createOpaqueRecipientCapabilityStore({
        capacity: 4,
        perSessionCapacity: 2,
        random() {
          return Buffer.alloc(
            32,
            seed++
          );
        }
      });

    const first = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasA,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasA),
      now: 1
    });

    const second = store.issue({
      subject: viewerA,
      sessionId: sessionA,
      alias: aliasB,
      purpose:
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
      currentAliases:
        currentAliases(aliasB),
      now: 2
    });

    assert.equal(
      first.state,
      "available"
    );

    assert.equal(
      second.state,
      "available"
    );

    assert.strictEqual(
      store.issue({
        subject: viewerA,
        sessionId: sessionA,
        alias: aliasA,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 3
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.equal(
      store.issue({
        subject: viewerA,
        sessionId: sessionB,
        alias: aliasA,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 3
      }).state,
      "available"
    );
  }
);

test(
  "per-subject quota cannot be bypassed by opening additional sessions",
  () => {
    let seed = 1;

    const otherSubject =
      "c".repeat(64);

    const sessionC =
      "D".repeat(43);

    const store =
      createOpaqueRecipientCapabilityStore({
        capacity: 6,
        perSessionCapacity: 2,
        perSubjectCapacity: 3,
        random() {
          return Buffer.alloc(
            32,
            seed++
          );
        }
      });

    for (const [
      selectedSession,
      selectedAlias,
      selectedNow
    ] of [
      [sessionA, aliasA, 1],
      [sessionA, aliasB, 2],
      [sessionB, aliasA, 3]
    ]) {
      assert.equal(
        store.issue({
          subject: viewerA,
          sessionId:
            selectedSession,
          alias:
            selectedAlias,
          purpose:
            OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
          currentAliases:
            currentAliases(
              selectedAlias
            ),
          now:
            selectedNow
        }).state,
        "available"
      );
    }

    assert.strictEqual(
      store.issue({
        subject: viewerA,
        sessionId: sessionB,
        alias: aliasB,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasB),
        now: 4
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.equal(
      store.issue({
        subject:
          otherSubject,
        sessionId:
          sessionC,
        alias:
          aliasA,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        currentAliases:
          currentAliases(aliasA),
        now: 4
      }).state,
      "available"
    );
  }
);

test(
  "capability core has no transport persistence authority X25519 or Nostr path",
  async () => {
    const source = await readFile(
      new URL(
        "../src/server/opaque-recipient-capability.mjs",
        import.meta.url
      ),
      "utf8"
    );

    for (const forbidden of [
      "fetch(",
      "XMLHttpRequest",
      "WebSocket",
      "EventSource",
      "localStorage",
      "sessionStorage",
      "indexedDB",
      "x25519",
      "X25519",
      "nostr",
      "Nostr",
      "grantFull",
      "issueCRT",
      "/auth/",
      "/internal/",
      "viewerAccessToken"
    ]) {
      assert.equal(
        source.includes(forbidden),
        false,
        forbidden
      );
    }

    assert.equal(
      source.includes(
        'from "node:crypto"'
      ),
      true
    );
  }
);
