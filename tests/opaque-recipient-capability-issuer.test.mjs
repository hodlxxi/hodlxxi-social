import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createOpaqueRecipientCapabilityIssuer
} from "../src/server/opaque-recipient-capability-issuer.mjs";

const subject = "e".repeat(64);
const sessionId = "S".repeat(43);

const aliasA =
  "p_KHcJHzAgVKtH830W3gJGIg";

const aliasB =
  "p_o8YlA6r_0WQmPpOfJp4aXA";

const capability =
  `rc_${"C".repeat(43)}`;

const now = 10_000;

const validSession = () => ({
  subject,
  viewerAccessToken:
    "private-human-bearer",
  issuedAt: 1_000,
  expiresAt: 20_000
});

const validDirectory = () => ({
  state: "available",
  participants: [
    { alias: aliasA },
    { alias: aliasB }
  ]
});

const setup = ({
  session = validSession(),
  authority = {
    subject,
    status: "full",
    valid: true
  },
  directory = validDirectory(),
  issued = {
    state: "available",
    capability,
    expiresAt: now + 60_000
  }
} = {}) => {
  const seen = {
    sessions: [],
    authority: [],
    directory: [],
    capability: []
  };

  const sessions = {
    get(candidate) {
      seen.sessions.push(candidate);
      return session;
    }
  };

  const fullDirectoryClient = {
    async readForViewer(input) {
      seen.directory.push(input);

      if (
        directory instanceof Error
      ) {
        throw directory;
      }

      return directory;
    }
  };

  const capabilityStore = {
    issue(input) {
      seen.capability.push(input);

      if (
        issued instanceof Error
      ) {
        throw issued;
      }

      return issued;
    }
  };

  const authorityReader =
    async (candidate) => {
      seen.authority.push(
        candidate
      );

      if (
        authority instanceof Error
      ) {
        throw authority;
      }

      return authority;
    };

  const issuer =
    createOpaqueRecipientCapabilityIssuer({
      sessions,
      authorityReader,
      fullDirectoryClient,
      capabilityStore,
      clock: () => now
    });

  return {
    issuer,
    seen
  };
};

test(
  "derives subject session authority directory aliases and time only from trusted server dependencies",
  async () => {
    const { issuer, seen } =
      setup();

    const result =
      await issuer.issue({
        sessionId,
        alias: aliasA
      });

    assert.deepEqual(
      result,
      {
        state: "available",
        capability,
        expiresAt:
          now + 60_000
      }
    );

    assert.deepEqual(
      seen.sessions,
      [sessionId]
    );

    assert.deepEqual(
      seen.authority,
      [subject]
    );

    assert.deepEqual(
      seen.directory,
      [{
        viewerAccessToken:
          "private-human-bearer"
      }]
    );

    assert.deepEqual(
      seen.capability,
      [{
        subject,
        sessionId,
        alias: aliasA,
        purpose:
          "direct-message",
        currentAliases: [
          { alias: aliasA },
          { alias: aliasB }
        ],
        now
      }]
    );

    const serialized =
      JSON.stringify(result);

    assert.equal(
      serialized.includes(
        subject
      ),
      false
    );

    assert.equal(
      serialized.includes(
        aliasA
      ),
      false
    );

    assert.equal(
      serialized.includes(
        "private-human-bearer"
      ),
      false
    );

    assert.ok(
      Object.isFrozen(result)
    );
  }
);

test(
  "non-Full or malformed authority fails before directory and capability issuance",
  async () => {
    for (const authority of [
      {
        subject,
        status: "limited",
        valid: true
      },
      {
        subject,
        status: "full",
        valid: false
      },
      {
        subject:
          "f".repeat(64),
        status: "full",
        valid: true
      },
      {
        subject,
        status: "full",
        valid: true,
        extra: true
      }
    ]) {
      const {
        issuer,
        seen
      } =
        setup({ authority });

      assert.deepEqual(
        await issuer.issue({
          sessionId,
          alias: aliasA
        }),
        {
          state:
            "unavailable"
        }
      );

      assert.equal(
        seen.directory.length,
        0
      );

      assert.equal(
        seen.capability.length,
        0
      );
    }
  }
);

test(
  "missing malformed and stale sessions fail before authority",
  async () => {
    const candidates = [
      null,
      {
        subject,
        issuedAt: 1_000,
        expiresAt: 20_000
      },
      {
        ...validSession(),
        expiresAt: now
      },
      {
        ...validSession(),
        subject:
          subject.toUpperCase()
      },
      {
        ...validSession(),
        viewerAccessToken:
          "private bearer"
      },
      {
        ...validSession(),
        extra: true
      }
    ];

    for (
      const session of candidates
    ) {
      const {
        issuer,
        seen
      } =
        setup({ session });

      assert.deepEqual(
        await issuer.issue({
          sessionId,
          alias: aliasA
        }),
        {
          state:
            "unavailable"
        }
      );

      assert.equal(
        seen.authority.length,
        0
      );
    }
  }
);

test(
  "directory accepts aliases only and rejects raw metadata duplicates and unsafe identifiers",
  async () => {
    const hostile = [
      {
        state: "available",
        participants: [{
          alias: aliasA,
          subject
        }]
      },
      {
        state: "available",
        participants: [
          { alias: aliasA },
          { alias: aliasA }
        ]
      },
      {
        state: "available",
        participants: [{
          alias: subject
        }]
      },
      {
        state: "available",
        participants: [{
          alias: "xpub-secret"
        }]
      },
      {
        state: "available",
        participants: [{
          alias:
            "person@example.com"
        }]
      },
      {
        state: "available",
        participants:
          new Array(1)
      }
    ];

    for (
      const directory of hostile
    ) {
      const {
        issuer,
        seen
      } =
        setup({ directory });

      assert.deepEqual(
        await issuer.issue({
          sessionId,
          alias: aliasA
        }),
        {
          state:
            "unavailable"
        }
      );

      assert.equal(
        seen.capability.length,
        0
      );
    }
  }
);

test(
  "selected alias must exist in the freshly accepted directory",
  async () => {
    const {
      issuer,
      seen
    } =
      setup({
        directory: {
          state: "available",
          participants: [{
            alias: aliasB
          }]
        }
      });

    assert.deepEqual(
      await issuer.issue({
        sessionId,
        alias: aliasA
      }),
      {
        state: "unavailable"
      }
    );

    assert.equal(
      seen.capability.length,
      0
    );
  }
);

test(
  "malformed caller input cannot supply subject time directory or execute accessors",
  async () => {
    let getterCalls = 0;

    const hostile = {};

    Object.defineProperty(
      hostile,
      "alias",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return aliasA;
        }
      }
    );

    Object.defineProperty(
      hostile,
      "sessionId",
      {
        enumerable: true,
        value: sessionId
      }
    );

    const {
      issuer,
      seen
    } = setup();

    for (const input of [
      hostile,
      {
        sessionId,
        alias: aliasA,
        subject
      },
      {
        sessionId,
        alias: aliasA,
        now
      },
      {
        sessionId,
        alias: aliasA,
        currentAliases: [{
          alias: aliasA
        }]
      }
    ]) {
      assert.deepEqual(
        await issuer.issue(input),
        {
          state:
            "unavailable"
        }
      );
    }

    assert.equal(
      getterCalls,
      0
    );

    assert.equal(
      seen.sessions.length,
      0
    );
  }
);

test(
  "throwing dependencies and malformed capability results fail closed without leakage",
  async () => {
    for (const selected of [
      {
        authority:
          new Error(
            "authority raw subject"
          )
      },
      {
        directory:
          new Error(
            "UBID has 42 participants"
          )
      },
      {
        issued:
          new Error(
            "capability internals"
          )
      },
      {
        issued: {
          state: "available",
          capability,
          expiresAt:
            now + 60_000,
          alias: aliasA
        }
      },
      {
        issued: {
          state: "available",
          capability:
            "not-a-capability",
          expiresAt:
            now + 60_000
        }
      },
      {
        issued: {
          state: "available",
          capability,
          expiresAt:
            now + 300_001
        }
      }
    ]) {
      const { issuer } =
        setup(selected);

      const result =
        await issuer.issue({
          sessionId,
          alias: aliasA
        });

      assert.deepEqual(
        result,
        {
          state:
            "unavailable"
        }
      );

      assert.doesNotMatch(
        JSON.stringify(
          result
        ),
        /42|subject|alias|UBID|internals/i
      );
    }
  }
);

test(
  "trusted issuer source adds no HTTP route browser persistence X25519 or Nostr path",
  async () => {
    const source =
      await readFile(
        new URL(
          "../src/server/opaque-recipient-capability-issuer.mjs",
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
      "/auth/",
      "/internal/",
      "x25519",
      "X25519",
      "nostr",
      "Nostr"
    ]) {
      assert.equal(
        source.includes(
          forbidden
        ),
        false,
        forbidden
      );
    }

    assert.equal(
      source.includes(
        "viewerAccessToken"
      ),
      true
    );

    assert.equal(
      source.includes(
        "currentAliases"
      ),
      true
    );
  }
);
