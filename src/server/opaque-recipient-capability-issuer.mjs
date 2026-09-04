import {
  MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS,
  OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
  OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
} from "./opaque-recipient-capability.mjs";

const SUBJECT = /^[0-9a-f]{64}$/;
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;
const SAFE_ALIAS = /^[A-Za-z0-9._~-]{1,128}$/;
const CAPABILITY = /^rc_[A-Za-z0-9_-]{43}$/;
const MAX_PARTICIPANTS = 4096;

const UNSAFE_ALIAS =
  /^(?:[0-9a-f]{64}|npub1|nprofile1|nsec1|xpub|tpub|ypub|zpub|vpub|xprv|tprv|yprv|zprv|vprv|bc1|tb1)/i;

const BITCOIN_BASE58_ADDRESS =
  /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/;

const exactRecord = (value, fields) => {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !==
        Object.prototype
    ) {
      return undefined;
    }

    const descriptors =
      Object.getOwnPropertyDescriptors(value);

    const keys =
      Reflect.ownKeys(descriptors);

    if (
      keys.length !== fields.length ||
      !fields.every(
        (field) => keys.includes(field)
      )
    ) {
      return undefined;
    }

    if (
      !keys.every(
        (key) =>
          typeof key === "string" &&
          fields.includes(key) &&
          descriptors[key].enumerable &&
          Object.hasOwn(
            descriptors[key],
            "value"
          )
      )
    ) {
      return undefined;
    }

    return Object.fromEntries(
      fields.map(
        (field) => [
          field,
          descriptors[field].value
        ]
      )
    );
  } catch {
    return undefined;
  }
};

const dataMethod = (value, name) => {
  try {
    if (
      value === null ||
      typeof value !== "object"
    ) {
      return undefined;
    }

    const descriptor =
      Object.getOwnPropertyDescriptor(
        value,
        name
      );

    return (
      descriptor &&
      Object.hasOwn(
        descriptor,
        "value"
      ) &&
      typeof descriptor.value ===
        "function"
    )
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
};

const canonicalSubject = (value) =>
  typeof value === "string" &&
  SUBJECT.test(value)
    ? value
    : undefined;

const canonicalSessionId = (value) =>
  typeof value === "string" &&
  SESSION_ID.test(value)
    ? value
    : undefined;

const privacySafeAlias = (value) =>
  typeof value === "string" &&
  SAFE_ALIAS.test(value) &&
  !UNSAFE_ALIAS.test(value) &&
  !BITCOIN_BASE58_ADDRESS.test(value) &&
  !/^\d{7,15}$/.test(value) &&
  !value.includes("@")
    ? value
    : undefined;

const safeInteger = (value) =>
  Number.isSafeInteger(value) &&
  value >= 0
    ? value
    : undefined;

const normalizeSession = (
  value,
  now
) => {
  const session =
    exactRecord(
      value,
      [
        "subject",
        "viewerAccessToken",
        "issuedAt",
        "expiresAt"
      ]
    );

  const subject =
    canonicalSubject(
      session?.subject
    );

  const issuedAt =
    safeInteger(
      session?.issuedAt
    );

  const expiresAt =
    safeInteger(
      session?.expiresAt
    );

  const viewerAccessToken =
    session?.viewerAccessToken;

  if (
    !session ||
    !subject ||
    issuedAt === undefined ||
    expiresAt === undefined ||
    issuedAt > now ||
    expiresAt <= now ||
    issuedAt >= expiresAt ||
    typeof viewerAccessToken !==
      "string" ||
    viewerAccessToken.length === 0 ||
    viewerAccessToken.length > 8192 ||
    /[\u0000-\u0020\u007f]/.test(
      viewerAccessToken
    )
  ) {
    return undefined;
  }

  return Object.freeze({
    subject,
    viewerAccessToken
  });
};

const normalizeFullAuthority = (
  subject,
  value
) => {
  const projection =
    exactRecord(
      value,
      [
        "subject",
        "status",
        "valid"
      ]
    );

  return (
    projection &&
    projection.subject === subject &&
    projection.status === "full" &&
    projection.valid === true
  )
    ? Object.freeze({
        subject,
        status: "full",
        valid: true
      })
    : undefined;
};

const normalizeDirectory = (value) => {
  const directory =
    exactRecord(
      value,
      [
        "state",
        "participants"
      ]
    );

  if (
    !directory ||
    directory.state !== "available" ||
    !Array.isArray(
      directory.participants
    ) ||
    Object.getPrototypeOf(
      directory.participants
    ) !== Array.prototype ||
    directory.participants.length >
      MAX_PARTICIPANTS
  ) {
    return undefined;
  }

  const descriptors =
    Object.getOwnPropertyDescriptors(
      directory.participants
    );

  if (
    Reflect.ownKeys(
      descriptors
    ).length !==
      directory.participants.length + 1
  ) {
    return undefined;
  }

  const participants = [];
  const seen = new Set();

  for (
    let index = 0;
    index <
      directory.participants.length;
    index += 1
  ) {
    const descriptor =
      descriptors[String(index)];

    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(
        descriptor,
        "value"
      )
    ) {
      return undefined;
    }

    const participant =
      exactRecord(
        descriptor.value,
        ["alias"]
      );

    const alias =
      privacySafeAlias(
        participant?.alias
      );

    if (
      !participant ||
      !alias ||
      seen.has(alias)
    ) {
      return undefined;
    }

    seen.add(alias);

    participants.push(
      Object.freeze({ alias })
    );
  }

  return Object.freeze(
    participants
  );
};

const normalizeIssuedCapability = (
  value,
  now
) => {
  const issued =
    exactRecord(
      value,
      [
        "state",
        "capability",
        "expiresAt"
      ]
    );

  const expiresAt =
    safeInteger(
      issued?.expiresAt
    );

  if (
    !issued ||
    issued.state !== "available" ||
    typeof issued.capability !==
      "string" ||
    !CAPABILITY.test(
      issued.capability
    ) ||
    expiresAt === undefined ||
    expiresAt <= now ||
    now >
      Number.MAX_SAFE_INTEGER -
        MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS ||
    expiresAt >
      now +
        MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS
  ) {
    return undefined;
  }

  return Object.freeze({
    state: "available",
    capability:
      issued.capability,
    expiresAt
  });
};

export function createOpaqueRecipientCapabilityIssuer({
  sessions,
  authorityReader,
  fullDirectoryClient,
  capabilityStore,
  clock = Date.now
} = {}) {
  const sessionGet =
    dataMethod(
      sessions,
      "get"
    );

  const directoryRead =
    dataMethod(
      fullDirectoryClient,
      "readForViewer"
    );

  const capabilityIssue =
    dataMethod(
      capabilityStore,
      "issue"
    );

  if (
    !sessionGet ||
    typeof authorityReader !==
      "function" ||
    !directoryRead ||
    !capabilityIssue ||
    typeof clock !== "function"
  ) {
    throw new TypeError(
      "invalid opaque recipient issuer dependencies"
    );
  }

  const issue = async (input) => {
    const request =
      exactRecord(
        input,
        [
          "sessionId",
          "alias"
        ]
      );

    const sessionId =
      canonicalSessionId(
        request?.sessionId
      );

    const alias =
      privacySafeAlias(
        request?.alias
      );

    if (
      !request ||
      !sessionId ||
      !alias
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    let now;

    try {
      now =
        safeInteger(clock());
    } catch {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    if (
      now === undefined ||
      now >
        Number.MAX_SAFE_INTEGER -
          MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    try {
      const session =
        normalizeSession(
          sessionGet.call(
            sessions,
            sessionId
          ),
          now
        );

      if (!session) {
        return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
      }

      const authority =
        normalizeFullAuthority(
          session.subject,
          await authorityReader(
            session.subject
          )
        );

      if (!authority) {
        return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
      }

      const participants =
        normalizeDirectory(
          await directoryRead.call(
            fullDirectoryClient,
            {
              viewerAccessToken:
                session.viewerAccessToken
            }
          )
        );

      if (
        !participants ||
        !participants.some(
          (participant) =>
            participant.alias === alias
        )
      ) {
        return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
      }

      const issued =
        normalizeIssuedCapability(
          capabilityIssue.call(
            capabilityStore,
            {
              subject:
                session.subject,
              sessionId,
              alias,
              purpose:
                OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
              currentAliases:
                participants,
              now
            }
          ),
          now
        );

      return (
        issued ??
        OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE
      );
    } catch {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }
  };

  return Object.freeze({
    issue
  });
}
