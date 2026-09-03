import { randomBytes } from "node:crypto";

export const OPAQUE_RECIPIENT_CAPABILITY_PURPOSE =
  "direct-message";

export const OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE =
  Object.freeze({ state: "unavailable" });

export const DEFAULT_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS =
  60_000;

export const MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS =
  300_000;

export const MAX_OPAQUE_RECIPIENT_CAPABILITIES =
  4096;

export const DEFAULT_OPAQUE_RECIPIENT_CAPABILITIES_PER_SESSION =
  16;

export const MAX_OPAQUE_RECIPIENT_CAPABILITIES_PER_SESSION =
  256;

export const DEFAULT_OPAQUE_RECIPIENT_CAPABILITIES_PER_SUBJECT =
  64;

export const MAX_OPAQUE_RECIPIENT_CAPABILITIES_PER_SUBJECT =
  1024;

const SUBJECT = /^[0-9a-f]{64}$/;
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;
const SAFE_ALIAS = /^[A-Za-z0-9._~-]{1,128}$/;
const CAPABILITY = /^rc_[A-Za-z0-9_-]{43}$/;

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
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      return undefined;
    }

    const descriptors =
      Object.getOwnPropertyDescriptors(value);

    const keys =
      Reflect.ownKeys(descriptors);

    if (
      keys.length !== fields.length ||
      !fields.every((field) => keys.includes(field))
    ) {
      return undefined;
    }

    if (
      !keys.every(
        (key) =>
          typeof key === "string" &&
          fields.includes(key) &&
          descriptors[key].enumerable &&
          Object.hasOwn(descriptors[key], "value")
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

const denseDataArray = (value) => {
  try {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !==
        Array.prototype
    ) {
      return undefined;
    }

    const descriptors =
      Object.getOwnPropertyDescriptors(value);

    const length =
      descriptors.length?.value;

    if (
      !Number.isSafeInteger(length) ||
      length < 0
    ) {
      return undefined;
    }

    const keys =
      Reflect.ownKeys(descriptors);

    if (
      keys.length !== length + 1 ||
      !keys.every(
        (key) =>
          key === "length" ||
          (
            typeof key === "string" &&
            /^(0|[1-9]\d*)$/.test(key)
          )
      )
    ) {
      return undefined;
    }

    const items = [];

    for (
      let index = 0;
      index < length;
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

      items.push(descriptor.value);
    }

    return items;
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

const safeNow = (value) =>
  Number.isSafeInteger(value) &&
  value >= 0
    ? value
    : undefined;

const normalizeCurrentAliases = (value) => {
  const items =
    denseDataArray(value);

  if (
    !items ||
    items.length >
      MAX_OPAQUE_RECIPIENT_CAPABILITIES
  ) {
    return undefined;
  }

  const aliases = [];
  const seen = new Set();

  for (const item of items) {
    const record =
      exactRecord(item, ["alias"]);

    const alias =
      privacySafeAlias(record?.alias);

    if (
      !record ||
      !alias ||
      seen.has(alias)
    ) {
      return undefined;
    }

    seen.add(alias);
    aliases.push(alias);
  }

  return Object.freeze(aliases);
};

const base64url = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");

const randomCapability = (random) => {
  try {
    const value = random(32);

    if (
      !(
        Buffer.isBuffer(value) ||
        value instanceof Uint8Array
      ) ||
      value.byteLength !== 32
    ) {
      return undefined;
    }

    const capability =
      `rc_${base64url(value)}`;

    return CAPABILITY.test(capability)
      ? capability
      : undefined;
  } catch {
    return undefined;
  }
};

export function createOpaqueRecipientCapabilityStore({
  random = randomBytes,
  ttlMs =
    DEFAULT_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS,
  capacity =
    MAX_OPAQUE_RECIPIENT_CAPABILITIES,
  perSessionCapacity,
  perSubjectCapacity
} = {}) {
  const sessionCapacity =
    perSessionCapacity === undefined
      ? Math.min(
          DEFAULT_OPAQUE_RECIPIENT_CAPABILITIES_PER_SESSION,
          capacity
        )
      : perSessionCapacity;

  const subjectCapacity =
    perSubjectCapacity === undefined
      ? Math.min(
          DEFAULT_OPAQUE_RECIPIENT_CAPABILITIES_PER_SUBJECT,
          capacity
        )
      : perSubjectCapacity;

  if (
    typeof random !== "function" ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs < 1 ||
    ttlMs >
      MAX_OPAQUE_RECIPIENT_CAPABILITY_TTL_MS ||
    !Number.isSafeInteger(capacity) ||
    capacity < 1 ||
    capacity >
      MAX_OPAQUE_RECIPIENT_CAPABILITIES ||
    !Number.isSafeInteger(
      sessionCapacity
    ) ||
    sessionCapacity < 1 ||
    sessionCapacity >
      MAX_OPAQUE_RECIPIENT_CAPABILITIES_PER_SESSION ||
    sessionCapacity > capacity ||
    !Number.isSafeInteger(
      subjectCapacity
    ) ||
    subjectCapacity < 1 ||
    subjectCapacity >
      MAX_OPAQUE_RECIPIENT_CAPABILITIES_PER_SUBJECT ||
    subjectCapacity > capacity ||
    sessionCapacity > subjectCapacity
  ) {
    throw new TypeError(
      "invalid opaque recipient capability configuration"
    );
  }

  const records = new Map();

  const sweep = (now) => {
    for (const [
      capability,
      record
    ] of records) {
      if (record.expiresAt <= now) {
        records.delete(capability);
      }
    }
  };

  const issue = (input) => {
    const record =
      exactRecord(
        input,
        [
          "subject",
          "sessionId",
          "alias",
          "purpose",
          "currentAliases",
          "now"
        ]
      );

    const subject =
      canonicalSubject(record?.subject);

    const sessionId =
      canonicalSessionId(record?.sessionId);

    const alias =
      privacySafeAlias(record?.alias);

    const now =
      safeNow(record?.now);

    const currentAliases =
      normalizeCurrentAliases(
        record?.currentAliases
      );

    if (
      !record ||
      !subject ||
      !sessionId ||
      !alias ||
      now === undefined ||
      record.purpose !==
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE ||
      !currentAliases ||
      !currentAliases.includes(alias)
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    if (
      now >
      Number.MAX_SAFE_INTEGER - ttlMs
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    sweep(now);

    if (records.size >= capacity) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    let sessionOutstanding = 0;
    let subjectOutstanding = 0;

    for (const stored of records.values()) {
      if (
        stored.subject === subject
      ) {
        subjectOutstanding += 1;
      }

      if (
        stored.sessionId === sessionId
      ) {
        sessionOutstanding += 1;
      }
    }

    if (
      sessionOutstanding >=
        sessionCapacity ||
      subjectOutstanding >=
        subjectCapacity
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    let capability;

    for (
      let attempt = 0;
      attempt < 4;
      attempt += 1
    ) {
      const candidate =
        randomCapability(random);

      if (
        candidate &&
        !records.has(candidate)
      ) {
        capability = candidate;
        break;
      }
    }

    if (!capability) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    const expiresAt =
      now + ttlMs;

    records.set(
      capability,
      Object.freeze({
        subject,
        sessionId,
        alias,
        purpose:
          OPAQUE_RECIPIENT_CAPABILITY_PURPOSE,
        expiresAt
      })
    );

    return Object.freeze({
      state: "available",
      capability,
      expiresAt
    });
  };

  const resolve = (input) => {
    const request =
      exactRecord(
        input,
        [
          "subject",
          "sessionId",
          "capability",
          "purpose",
          "currentAliases",
          "now"
        ]
      );

    const subject =
      canonicalSubject(request?.subject);

    const sessionId =
      canonicalSessionId(request?.sessionId);

    const now =
      safeNow(request?.now);

    const currentAliases =
      normalizeCurrentAliases(
        request?.currentAliases
      );

    if (
      !request ||
      !subject ||
      !sessionId ||
      now === undefined ||
      typeof request.capability !==
        "string" ||
      !CAPABILITY.test(
        request.capability
      ) ||
      request.purpose !==
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE ||
      !currentAliases
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    sweep(now);

    const stored =
      records.get(request.capability);

    if (
      !stored ||
      stored.subject !== subject ||
      stored.sessionId !== sessionId ||
      stored.purpose !==
        OPAQUE_RECIPIENT_CAPABILITY_PURPOSE ||
      stored.expiresAt <= now ||
      !currentAliases.includes(
        stored.alias
      )
    ) {
      return OPAQUE_RECIPIENT_CAPABILITY_UNAVAILABLE;
    }

    return Object.freeze({
      state: "available",
      alias: stored.alias
    });
  };

  return Object.freeze({
    issue,
    resolve
  });
}
