import {
  canonicalNostrRelayUrl
} from "./authenticated-public-read.mjs?v=1.28.1";

import {
  verifyNostrEvent
} from "./nostr-event-verifier.mjs?v=1.28.1";

const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const MAX_PROFILE_NAME = 80;
const MAX_PROFILE_ABOUT = 280;
const MAX_NOTE_CHARACTERS = 5_000;
const MAX_NOTE_BYTES = 20_000;
const MAX_ACK_BYTES = 4_096;
const MAX_ACK_MESSAGE = 512;
const DEFAULT_TIMEOUT_MS = 5_000;

export const AUTHENTICATED_SIGNER_STATES = Object.freeze({
  connected: "connected",
  mismatch: "mismatch",
  unavailable: "unavailable"
});

const signerResult = (state, publicKey = null) => Object.freeze(
  publicKey === null ? { state } : { state, publicKey }
);

const fixedSignerFailure = (state) => signerResult(state);
const fixedWriteFailure = () => {
  throw new TypeError("authenticated Nostr publication unavailable");
};

const validSubject = (value) =>
  typeof value === "string" && CANONICAL_SUBJECT.test(value);

const boundedTimeout = (value) => {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 30_000
  ) {
    fixedWriteFailure();
  }
  return value;
};

const resolveMethod = (provider, name) => {
  if (
    provider === null ||
    typeof provider !== "object"
  ) {
    fixedWriteFailure();
  }

  let method;
  try {
    method = provider[name];
  } catch {
    fixedWriteFailure();
  }

  if (typeof method !== "function") fixedWriteFailure();
  return method;
};

const asOwnedPromise = (value) => {
  if (
    (typeof value === "object" && value !== null) ||
    typeof value === "function"
  ) {
    try {
      return Promise.prototype.then.call(value, (result) => result);
    } catch {
      fixedWriteFailure();
    }
  }

  return Promise.resolve(value);
};

const callProvider = async (
  provider,
  method,
  args,
  {
    timeoutMs,
    setTimer,
    clearTimer
  }
) => {
  let direct;
  try {
    direct = method.call(provider, ...args);
  } catch {
    fixedWriteFailure();
  }

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimer(
      () => reject(new TypeError("authenticated signer timeout")),
      timeoutMs
    );
  });

  try {
    return await Promise.race([asOwnedPromise(direct), timeout]);
  } catch {
    fixedWriteFailure();
  } finally {
    direct = undefined;
    if (timer !== undefined) clearTimer(timer);
  }
};

const signerDependencies = ({
  resolveProvider,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  setTimer = setTimeout,
  clearTimer = clearTimeout
} = {}) => {
  if (
    typeof resolveProvider !== "function" ||
    typeof setTimer !== "function" ||
    typeof clearTimer !== "function"
  ) {
    fixedWriteFailure();
  }

  return Object.freeze({
    resolveProvider,
    timeoutMs: boundedTimeout(timeoutMs),
    setTimer,
    clearTimer
  });
};

const resolveProvider = (resolveImpl) => {
  let provider;
  try {
    provider = resolveImpl();
  } catch {
    fixedWriteFailure();
  }

  if (
    provider === null ||
    typeof provider !== "object"
  ) {
    fixedWriteFailure();
  }

  return provider;
};

export async function connectAuthenticatedNip07Signer(
  { subject } = {},
  dependencies = {}
) {
  if (!validSubject(subject)) {
    return fixedSignerFailure(AUTHENTICATED_SIGNER_STATES.unavailable);
  }

  let checked;
  let provider;
  try {
    checked = signerDependencies(dependencies);
    provider = resolveProvider(checked.resolveProvider);
    const getPublicKey = resolveMethod(provider, "getPublicKey");
    const publicKey = await callProvider(
      provider,
      getPublicKey,
      [],
      checked
    );

    if (!validSubject(publicKey)) {
      return fixedSignerFailure(AUTHENTICATED_SIGNER_STATES.unavailable);
    }

    return publicKey === subject
      ? signerResult(AUTHENTICATED_SIGNER_STATES.connected, subject)
      : fixedSignerFailure(AUTHENTICATED_SIGNER_STATES.mismatch);
  } catch {
    return fixedSignerFailure(AUTHENTICATED_SIGNER_STATES.unavailable);
  } finally {
    provider = undefined;
    checked = undefined;
  }
}

const profileText = (value, maximum) => {
  if (typeof value !== "string") fixedWriteFailure();
  const normalized = value
    .normalize("NFKC")
    .replace(/[\p{Cc}\p{Cf}]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();

  if ([...normalized].length > maximum) fixedWriteFailure();
  return normalized || null;
};

export function createAuthenticatedProfileContent({
  displayName,
  about
} = {}) {
  const normalizedName = profileText(displayName, MAX_PROFILE_NAME);
  const normalizedAbout = profileText(about, MAX_PROFILE_ABOUT);

  if (normalizedName === null && normalizedAbout === null) {
    fixedWriteFailure();
  }

  const profile = {};
  if (normalizedName !== null) profile.display_name = normalizedName;
  if (normalizedAbout !== null) profile.about = normalizedAbout;
  return JSON.stringify(profile);
}

export function createAuthenticatedNoteContent(value) {
  if (typeof value !== "string") fixedWriteFailure();
  const normalized = value.normalize("NFC").trim();

  if (
    normalized.length === 0 ||
    [...normalized].length > MAX_NOTE_CHARACTERS ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized) ||
    new TextEncoder().encode(normalized).byteLength > MAX_NOTE_BYTES
  ) {
    fixedWriteFailure();
  }

  return normalized;
}

const tagsEqual = (left, right) =>
  Array.isArray(left) &&
  Array.isArray(right) &&
  left.length === right.length &&
  left.every((tag, index) =>
    Array.isArray(tag) &&
    Array.isArray(right[index]) &&
    tag.length === right[index].length &&
    tag.every((value, valueIndex) => value === right[index][valueIndex])
  );

export async function signAuthenticatedNostrEvent(
  {
    subject,
    kind,
    content,
    tags = [],
    createdAt
  } = {},
  {
    resolveProvider,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    setTimer = setTimeout,
    clearTimer = clearTimeout,
    verifyEvent = verifyNostrEvent
  } = {}
) {
  if (
    !validSubject(subject) ||
    ![0, 1].includes(kind) ||
    typeof content !== "string" ||
    !Array.isArray(tags) ||
    tags.length !== 0 ||
    !Number.isSafeInteger(createdAt) ||
    createdAt < 0 ||
    typeof verifyEvent !== "function"
  ) {
    fixedWriteFailure();
  }

  const checked = signerDependencies({
    resolveProvider,
    timeoutMs,
    setTimer,
    clearTimer
  });
  let provider;

  try {
    provider = resolveProvider(checked.resolveProvider);
    const getPublicKey = resolveMethod(provider, "getPublicKey");
    const publicKey = await callProvider(
      provider,
      getPublicKey,
      [],
      checked
    );

    if (publicKey !== subject || !validSubject(publicKey)) {
      fixedWriteFailure();
    }

    const signEvent = resolveMethod(provider, "signEvent");
    const unsigned = {
      created_at: createdAt,
      kind,
      tags: [],
      content
    };
    const candidate = await callProvider(
      provider,
      signEvent,
      [unsigned],
      checked
    );
    const verified = await verifyEvent(candidate);

    if (
      verified.pubkey !== subject ||
      verified.created_at !== createdAt ||
      verified.kind !== kind ||
      verified.content !== content ||
      !tagsEqual(verified.tags, tags)
    ) {
      fixedWriteFailure();
    }

    return verified;
  } catch {
    fixedWriteFailure();
  } finally {
    provider = undefined;
  }
}

const defaultWebSocketFactory = (relayUrl) => {
  if (typeof globalThis.WebSocket !== "function") fixedWriteFailure();
  return new globalThis.WebSocket(relayUrl);
};

export async function publishSignedNostrEvent(
  {
    relayUrl,
    event
  } = {},
  {
    webSocketFactory = defaultWebSocketFactory,
    verifyEvent = verifyNostrEvent,
    openTimeoutMs = DEFAULT_TIMEOUT_MS,
    acknowledgeTimeoutMs = DEFAULT_TIMEOUT_MS,
    setTimer = setTimeout,
    clearTimer = clearTimeout
  } = {}
) {
  if (
    typeof webSocketFactory !== "function" ||
    typeof verifyEvent !== "function" ||
    typeof setTimer !== "function" ||
    typeof clearTimer !== "function"
  ) {
    fixedWriteFailure();
  }

  let canonicalRelay;
  try {
    canonicalRelay = canonicalNostrRelayUrl(relayUrl);
  } catch {
    fixedWriteFailure();
  }
  const checkedOpenTimeout = boundedTimeout(openTimeoutMs);
  const checkedAcknowledgeTimeout = boundedTimeout(acknowledgeTimeoutMs);
  let verified;
  try {
    verified = await verifyEvent(event);
  } catch {
    fixedWriteFailure();
  }

  return new Promise((resolve, reject) => {
    let socket;
    let openTimer;
    let acknowledgeTimer;
    let opened = false;
    let settled = false;

    const remove = (name, callback) => {
      try {
        socket?.removeEventListener?.(name, callback);
      } catch {
        // Cleanup is best effort after the result is fixed.
      }
    };

    const cleanup = () => {
      if (openTimer !== undefined) clearTimer(openTimer);
      if (acknowledgeTimer !== undefined) clearTimer(acknowledgeTimer);
      remove("open", onOpen);
      remove("message", onMessage);
      remove("error", onFailure);
      remove("close", onFailure);
      try {
        socket?.close?.();
      } catch {
        // Cleanup is best effort after the result is fixed.
      }
    };

    const finish = (error = null) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(new TypeError("authenticated Nostr publication unavailable"));
      else resolve(Object.freeze({
        accepted: true,
        eventId: verified.id,
        relayHost: new URL(canonicalRelay).host
      }));
    };

    function onOpen() {
      if (opened) {
        finish(new Error("duplicate open"));
        return;
      }
      opened = true;
      if (openTimer !== undefined) clearTimer(openTimer);

      try {
        socket.send(JSON.stringify(["EVENT", verified]));
      } catch {
        finish(new Error("send failed"));
        return;
      }

      acknowledgeTimer = setTimer(
        () => finish(new Error("acknowledgement timeout")),
        checkedAcknowledgeTimeout
      );
    }

    function onMessage(message) {
      let raw;
      try {
        raw = message.data;
      } catch {
        finish(new Error("invalid acknowledgement"));
        return;
      }

      if (
        typeof raw !== "string" ||
        new TextEncoder().encode(raw).byteLength > MAX_ACK_BYTES
      ) {
        finish(new Error("invalid acknowledgement"));
        return;
      }

      let frame;
      try {
        frame = JSON.parse(raw);
      } catch {
        finish(new Error("invalid acknowledgement"));
        return;
      }

      if (
        !opened ||
        !Array.isArray(frame) ||
        frame.length !== 4 ||
        frame[0] !== "OK" ||
        frame[1] !== verified.id ||
        typeof frame[2] !== "boolean" ||
        typeof frame[3] !== "string" ||
        frame[3].length > MAX_ACK_MESSAGE
      ) {
        finish(new Error("invalid acknowledgement"));
        return;
      }

      finish(frame[2] ? null : new Error("publication rejected"));
    }

    function onFailure() {
      finish(new Error("relay unavailable"));
    }

    try {
      socket = webSocketFactory(canonicalRelay);
      if (
        socket === null ||
        typeof socket !== "object" ||
        typeof socket.addEventListener !== "function" ||
        typeof socket.send !== "function" ||
        typeof socket.close !== "function"
      ) {
        finish(new Error("invalid relay transport"));
        return;
      }

      socket.addEventListener("open", onOpen);
      socket.addEventListener("message", onMessage);
      socket.addEventListener("error", onFailure);
      socket.addEventListener("close", onFailure);
      openTimer = setTimer(
        () => finish(new Error("open timeout")),
        checkedOpenTimeout
      );
    } catch {
      finish(new Error("relay unavailable"));
    }
  });
}

const currentEpochSeconds = () => Math.floor(Date.now() / 1_000);

const writeAuthenticatedEvent = async (
  {
    subject,
    relayUrl,
    kind,
    content
  },
  {
    now = currentEpochSeconds,
    signer = signAuthenticatedNostrEvent,
    publisher = publishSignedNostrEvent,
    ...dependencies
  } = {}
) => {
  if (
    typeof now !== "function" ||
    typeof signer !== "function" ||
    typeof publisher !== "function"
  ) {
    fixedWriteFailure();
  }

  let createdAt;
  try {
    createdAt = now();
  } catch {
    fixedWriteFailure();
  }

  const event = await signer(
    {
      subject,
      kind,
      content,
      tags: [],
      createdAt
    },
    dependencies
  );
  const receipt = await publisher(
    { relayUrl, event },
    dependencies
  );

  return Object.freeze({ event, receipt });
};

export function publishAuthenticatedProfile(
  {
    subject,
    relayUrl,
    displayName,
    about
  } = {},
  dependencies = {}
) {
  const content = createAuthenticatedProfileContent({ displayName, about });
  return writeAuthenticatedEvent(
    { subject, relayUrl, kind: 0, content },
    dependencies
  );
}

export function publishAuthenticatedNote(
  {
    subject,
    relayUrl,
    content
  } = {},
  dependencies = {}
) {
  return writeAuthenticatedEvent(
    {
      subject,
      relayUrl,
      kind: 1,
      content: createAuthenticatedNoteContent(content)
    },
    dependencies
  );
}
