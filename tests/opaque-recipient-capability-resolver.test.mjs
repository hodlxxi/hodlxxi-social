import assert from "node:assert/strict";
import test from "node:test";

import {
  OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
} from "../src/server/opaque-recipient-capability.mjs";
import {
  createOpaqueRecipientCapabilityResolver
} from "../src/server/opaque-recipient-capability-resolver.mjs";

const subject = "e".repeat(64);
const sessionId = "S".repeat(43);
const capability =
  `rc_${"C".repeat(43)}`;

const aliasA =
  "p_KHcJHzAgVKtH830W3gJGIg";

const aliasB =
  "p_o8YlA6r_0WQmPpOfJp4aXA";

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
  resolved = {
    state: "available",
    alias: aliasA
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
    resolve(input) {
      seen.capability.push(input);

      if (
        resolved instanceof Error
      ) {
        throw resolved;
      }

      return resolved;
    }
  };

  const resolver =
    createOpaqueRecipientCapabilityResolver({
      sessions,
      authorityReader,
      fullDirectoryClient,
      capabilityStore,
      clock: () => now
    });

  return {
    resolver,
    seen
  };
};

test(
  "redeems only through trusted session Full directory and store authority",
  async () => {
    const { resolver, seen } =
      setup();

    const result =
      await resolver.resolve({
        sessionId,
        capability
      });

    assert.deepEqual(
      result,
      {
        state: "available",
        alias: aliasA
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
        capability,
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
      serialized.includes(subject),
      false
    );

    assert.equal(
      serialized.includes(
        "private-human-bearer"
      ),
      false
    );

    assert.equal(
      serialized.includes(
        capability
      ),
      false
    );

    assert.ok(
      Object.isFrozen(result)
    );
  }
);

test(
  "non-Full or malformed current authority fails before directory and store resolution",
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
        resolver,
        seen
      } = setup({ authority });

      assert.strictEqual(
        await resolver.resolve({
          sessionId,
          capability
        }),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
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
  "expired malformed or mismatched session fails before current authority lookup",
  async () => {
    for (const session of [
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
        viewerAccessToken: ""
      },
      {
        ...validSession(),
        extra: true
      }
    ]) {
      const {
        resolver,
        seen
      } = setup({ session });

      assert.strictEqual(
        await resolver.resolve({
          sessionId,
          capability
        }),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );

      assert.equal(
        seen.authority.length,
        0
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
  "malformed fresh directory fails before capability resolution",
  async () => {
    for (const directory of [
      {
        state: "unavailable",
        participants: []
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
        participants: [
          {
            alias: aliasA,
            extra: true
          }
        ]
      },
      new Error(
        "directory unavailable"
      )
    ]) {
      const {
        resolver,
        seen
      } = setup({ directory });

      assert.strictEqual(
        await resolver.resolve({
          sessionId,
          capability
        }),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );

      assert.equal(
        seen.capability.length,
        0
      );
    }
  }
);

test(
  "malformed request is rejected before trusted dependency access",
  async () => {
    for (const request of [
      {
        sessionId,
        capability: "rc_bad"
      },
      {
        sessionId:
          "short",
        capability
      },
      {
        sessionId,
        capability,
        alias: aliasA
      },
      null
    ]) {
      const {
        resolver,
        seen
      } = setup();

      assert.strictEqual(
        await resolver.resolve(
          request
        ),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );

      assert.deepEqual(
        seen,
        {
          sessions: [],
          authority: [],
          directory: [],
          capability: []
        }
      );
    }
  }
);

test(
  "store denial exception or malformed result collapses to generic unavailable",
  async () => {
    for (const resolved of [
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE,
      new Error(
        "private store failure"
      ),
      {
        state: "available",
        alias: aliasA,
        subject
      },
      {
        state: "available",
        alias:
          "a".repeat(64)
      },
      {
        state: "available",
        alias: "not-current"
      }
    ]) {
      const { resolver } =
        setup({ resolved });

      assert.strictEqual(
        await resolver.resolve({
          sessionId,
          capability
        }),
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );
    }
  }
);

test(
  "successful resolver result must remain in the freshly accepted directory",
  async () => {
    const {
      resolver,
      seen
    } = setup({
      directory: {
        state: "available",
        participants: [
          { alias: aliasB }
        ]
      },
      resolved: {
        state: "available",
        alias: aliasA
      }
    });

    assert.strictEqual(
      await resolver.resolve({
        sessionId,
        capability
      }),
      OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
    );

    assert.equal(
      seen.capability.length,
      1
    );

    assert.deepEqual(
      seen.capability[0]
        .currentAliases,
      [{ alias: aliasB }]
    );
  }
);

test(
  "resolver does not consume a capability and may revalidate it repeatedly within store lifetime",
  async () => {
    const {
      resolver,
      seen
    } = setup();

    assert.equal(
      (
        await resolver.resolve({
          sessionId,
          capability
        })
      ).state,
      "available"
    );

    assert.equal(
      (
        await resolver.resolve({
          sessionId,
          capability
        })
      ).state,
      "available"
    );

    assert.equal(
      seen.capability.length,
      2
    );

    assert.deepEqual(
      seen.capability.map(
        (request) =>
          request.capability
      ),
      [
        capability,
        capability
      ]
    );
  }
);
