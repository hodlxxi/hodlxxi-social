import { verifyNostrEvent } from "./nostr-event-verifier.mjs?v=1.20.0";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const OPEN = 1;
const OPEN_TIMEOUT_MS = 4_000;
const READ_TIMEOUT_MS = 5_000;
const PROFILE_EVENT_LIMIT = 4;
const NOTE_EVENT_LIMIT = 10;
const MAX_MESSAGE_BYTES = 262_144;
const MAX_ACCUMULATED_BYTES = 1_048_576;
const MAX_NOTE_CHARACTERS = 5_000;
const EMPTY = Object.freeze([]);
let nextSubscription = 0;

const unavailableState = () => Object.freeze({
  relayHost: null,
  profileState: "unavailable",
  profile: null,
  notesState: "unavailable",
  notes: EMPTY
});

export const createPendingAuthenticatedPublicRead = () => Object.freeze({
  relayHost: null,
  profileState: "loading",
  profile: null,
  notesState: "loading",
  notes: EMPTY
});

export const createUnavailableAuthenticatedPublicRead = unavailableState;

const positiveInteger = (value, maximum, label) => {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`invalid ${label}`);
  }
  return value;
};

export function canonicalNostrRelayUrl(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    /[\u0000-\u0020\u007f]/.test(value)
  ) {
    throw new TypeError("invalid Nostr relay URL");
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("invalid Nostr relay URL");
  }

  if (
    parsed.protocol !== "wss:" ||
    !parsed.hostname ||
    parsed.hostname.endsWith(".") ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new TypeError("invalid Nostr relay URL");
  }

  return parsed.href;
}

const requireSocket = (value) => {
  if (
    !value ||
    typeof value.addEventListener !== "function" ||
    typeof value.removeEventListener !== "function" ||
    typeof value.send !== "function" ||
    typeof value.close !== "function" ||
    typeof value.readyState !== "number"
  ) {
    throw new TypeError("Nostr WebSocket unavailable");
  }
  return value;
};

const defaultWebSocketFactory = (relayUrl) => {
  if (typeof globalThis.WebSocket !== "function") {
    throw new TypeError("Nostr WebSocket unavailable");
  }
  return new globalThis.WebSocket(relayUrl);
};

export function readAuthenticatedNostrEvents(
  {
    relayUrl,
    subject,
    kind,
    limit,
    openTimeoutMs = OPEN_TIMEOUT_MS,
    readTimeoutMs = READ_TIMEOUT_MS
  },
  {
    webSocketFactory = defaultWebSocketFactory,
    subscriptionIdFactory = () => `social-auth-read-${++nextSubscription}`
  } = {}
) {
  const canonicalRelay = canonicalNostrRelayUrl(relayUrl);
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject) ||
    ![0, 1].includes(kind) ||
    typeof webSocketFactory !== "function" ||
    typeof subscriptionIdFactory !== "function"
  ) {
    return Promise.reject(new TypeError("invalid authenticated Nostr read"));
  }

  const maximum = kind === 0 ? PROFILE_EVENT_LIMIT : NOTE_EVENT_LIMIT;
  let checkedLimit;
  let checkedOpenTimeout;
  let checkedReadTimeout;
  try {
    checkedLimit = positiveInteger(limit, maximum, "Nostr event limit");
    checkedOpenTimeout = positiveInteger(openTimeoutMs, 30_000, "Nostr open timeout");
    checkedReadTimeout = positiveInteger(readTimeoutMs, 30_000, "Nostr read timeout");
  } catch (error) {
    return Promise.reject(error);
  }

  let subscriptionId;
  let socket;
  try {
    subscriptionId = subscriptionIdFactory();
    if (
      typeof subscriptionId !== "string" ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(subscriptionId)
    ) {
      throw new TypeError("invalid Nostr subscription");
    }
    socket = requireSocket(webSocketFactory(canonicalRelay));
  } catch (error) {
    return Promise.reject(error);
  }

  const filter = Object.freeze({
    authors: Object.freeze([subject]),
    kinds: Object.freeze([kind]),
    limit: checkedLimit
  });

  return new Promise((resolve, reject) => {
    const events = [];
    let accumulatedBytes = 0;
    let requestSent = false;
    let settled = false;
    let openTimer = null;
    let readTimer = null;

    const removeListeners = () => {
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("error", onError);
      socket.removeEventListener("close", onClose);
    };

    const cleanup = () => {
      clearTimeout(openTimer);
      clearTimeout(readTimer);
      removeListeners();
      if (requestSent && socket.readyState === OPEN) {
        try {
          socket.send(JSON.stringify(["CLOSE", subscriptionId]));
        } catch {
          // The read result is already fixed; close remains best effort.
        }
      }
      try {
        socket.close();
      } catch {
        // The read result is already fixed; close remains best effort.
      }
    };

    const finish = (failure = null) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (failure) reject(failure);
      else resolve(Object.freeze([...events]));
    };

    const fail = () => finish(new Error("authenticated Nostr read unavailable"));

    function onOpen() {
      if (requestSent) return fail();
      clearTimeout(openTimer);
      try {
        socket.send(JSON.stringify(["REQ", subscriptionId, filter]));
        requestSent = true;
      } catch {
        fail();
      }
    }

    function onMessage(message) {
      if (!requestSent || typeof message?.data !== "string") return fail();
      const messageBytes = new TextEncoder().encode(message.data).byteLength;
      if (messageBytes > MAX_MESSAGE_BYTES) return fail();
      accumulatedBytes += messageBytes;
      if (accumulatedBytes > MAX_ACCUMULATED_BYTES) return fail();

      let frame;
      try {
        frame = JSON.parse(message.data);
      } catch {
        return fail();
      }

      if (!Array.isArray(frame) || typeof frame[0] !== "string") return fail();

      if (frame[0] === "EVENT") {
        if (
          frame.length !== 3 ||
          frame[1] !== subscriptionId ||
          !frame[2] ||
          typeof frame[2] !== "object" ||
          Array.isArray(frame[2])
        ) {
          return fail();
        }
        events.push(frame[2]);
        if (events.length >= checkedLimit) finish();
        return;
      }

      if (
        frame[0] === "EOSE" &&
        frame.length === 2 &&
        frame[1] === subscriptionId
      ) {
        finish();
        return;
      }

      fail();
    }

    function onError() {
      fail();
    }

    function onClose() {
      fail();
    }

    openTimer = setTimeout(fail, checkedOpenTimeout);
    readTimer = setTimeout(fail, checkedReadTimeout);
    socket.addEventListener("open", onOpen);
    socket.addEventListener("message", onMessage);
    socket.addEventListener("error", onError);
    socket.addEventListener("close", onClose);
  });
}

const cleanProfileText = (value, maximum) => {
  if (typeof value !== "string") return null;
  const normalized = value
    .normalize("NFKC")
    .replace(/[\p{Cc}\p{Cf}]/gu, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maximum);
  return normalized || null;
};

const mapProfile = (event) => {
  let content;
  try {
    content = JSON.parse(event.content);
  } catch {
    throw new TypeError("invalid Nostr profile metadata");
  }

  if (
    content === null ||
    typeof content !== "object" ||
    Array.isArray(content) ||
    Object.getPrototypeOf(content) !== Object.prototype
  ) {
    throw new TypeError("invalid Nostr profile metadata");
  }

  return Object.freeze({
    displayName:
      cleanProfileText(content.display_name, 80) ??
      cleanProfileText(content.name, 80),
    about: cleanProfileText(content.about, 280),
    eventId: event.id,
    createdAt: new Date(event.created_at * 1_000).toISOString()
  });
};

const mapNote = (event) => Object.freeze({
  id: event.id,
  body: event.content
    .normalize("NFC")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "�")
    .slice(0, MAX_NOTE_CHARACTERS),
  createdAt: new Date(event.created_at * 1_000).toISOString()
});

const verifyExactEvents = async (
  events,
  { subject, kind, limit, verifyEvent }
) => {
  if (!Array.isArray(events) || events.length > limit) {
    throw new TypeError("invalid Nostr read result");
  }

  const verified = [];
  for (const event of events) {
    if (
      !event ||
      typeof event !== "object" ||
      event.pubkey !== subject ||
      event.kind !== kind
    ) {
      throw new TypeError("off-subject Nostr read result");
    }

    const checked = await verifyEvent(event);
    if (checked.pubkey !== subject || checked.kind !== kind) {
      throw new TypeError("off-subject Nostr read result");
    }
    verified.push(checked);
  }

  return Object.freeze(verified);
};

const loadProfile = async (
  input,
  { readEvents, verifyEvent }
) => {
  const events = await readEvents({
    ...input,
    kind: 0,
    limit: PROFILE_EVENT_LIMIT
  });
  const verified = await verifyExactEvents(events, {
    subject: input.subject,
    kind: 0,
    limit: PROFILE_EVENT_LIMIT,
    verifyEvent
  });

  const latest = [...verified].sort((left, right) =>
    right.created_at - left.created_at || left.id.localeCompare(right.id)
  )[0];
  return latest ? mapProfile(latest) : null;
};

const loadNotes = async (
  input,
  { readEvents, verifyEvent }
) => {
  const events = await readEvents({
    ...input,
    kind: 1,
    limit: NOTE_EVENT_LIMIT
  });
  const verified = await verifyExactEvents(events, {
    subject: input.subject,
    kind: 1,
    limit: NOTE_EVENT_LIMIT,
    verifyEvent
  });
  const unique = new Map();
  for (const event of verified) unique.set(event.id, event);

  return Object.freeze(
    [...unique.values()]
      .sort((left, right) =>
        right.created_at - left.created_at || left.id.localeCompare(right.id)
      )
      .slice(0, NOTE_EVENT_LIMIT)
      .map(mapNote)
  );
};

export async function loadAuthenticatedPublicRead(
  { subject, relayUrl } = {},
  {
    readEvents = readAuthenticatedNostrEvents,
    verifyEvent = verifyNostrEvent
  } = {}
) {
  if (
    typeof subject !== "string" ||
    !CANONICAL_SUBJECT.test(subject) ||
    typeof readEvents !== "function" ||
    typeof verifyEvent !== "function"
  ) {
    throw new TypeError("invalid authenticated public read");
  }

  const canonicalRelay = canonicalNostrRelayUrl(relayUrl);
  const relayHost = new URL(canonicalRelay).host;
  const input = Object.freeze({
    subject,
    relayUrl: canonicalRelay
  });
  const dependencies = Object.freeze({ readEvents, verifyEvent });
  const [profileResult, notesResult] = await Promise.allSettled([
    loadProfile(input, dependencies),
    loadNotes(input, dependencies)
  ]);

  const profile = profileResult.status === "fulfilled"
    ? profileResult.value
    : null;
  const notes = notesResult.status === "fulfilled"
    ? notesResult.value
    : EMPTY;

  return Object.freeze({
    relayHost,
    profileState: profileResult.status === "rejected"
      ? "unavailable"
      : profile
        ? "available"
        : "empty",
    profile,
    notesState: notesResult.status === "rejected"
      ? "unavailable"
      : notes.length > 0
        ? "available"
        : "empty",
    notes
  });
}
