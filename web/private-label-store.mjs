const CANONICAL_SUBJECT = /^[0-9a-f]{64}$/;
const PRIVATE_ALIAS = /^[A-Za-z0-9._~-]{1,128}$/;

const STORAGE_PREFIX =
  "hodlxxi.social.private-labels.v1.";

const MAX_LABEL_CODEPOINTS = 64;
const MAX_LABEL_CODE_UNITS = 256;
const MAX_RECORDS = 4096;
const MAX_DOCUMENT_CHARACTERS = 1_048_576;

const exactKeys = (value, expected) => {
  const keys = Object.keys(value).sort();

  return (
    keys.length === expected.length &&
    expected.every((name, index) => keys[index] === name)
  );
};

const plainObject = (value) =>
  Boolean(value) &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const validSubject = (subject) =>
  typeof subject === "string" &&
  CANONICAL_SUBJECT.test(subject);

const validAlias = (alias) =>
  typeof alias === "string" &&
  PRIVATE_ALIAS.test(alias);

const storageKey = (subject) => {
  if (!validSubject(subject)) {
    throw new TypeError("invalid private-label viewer");
  }

  return `${STORAGE_PREFIX}${subject}`;
};

export function normalizePrivateLabel(value) {
  if (typeof value !== "string") {
    throw new TypeError("invalid private label");
  }

  const normalized = value
    .normalize("NFC")
    .replace(/\s+/gu, " ")
    .trim();

  if (normalized.length === 0) {
    return "";
  }

  if (
    normalized.length > MAX_LABEL_CODE_UNITS ||
    [...normalized].length > MAX_LABEL_CODEPOINTS ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new TypeError("invalid private label");
  }

  return normalized;
}

const emptyDocument = () =>
  Object.freeze({
    version: 1,
    labels: Object.freeze([])
  });

const parseDocument = (raw) => {
  if (raw === null) {
    return emptyDocument();
  }

  if (
    typeof raw !== "string" ||
    raw.length === 0 ||
    raw.length > MAX_DOCUMENT_CHARACTERS
  ) {
    throw new TypeError("invalid private-label document");
  }

  let value;

  try {
    value = JSON.parse(raw);
  } catch {
    throw new TypeError("invalid private-label document");
  }

  if (
    !plainObject(value) ||
    !exactKeys(value, ["labels", "version"]) ||
    value.version !== 1 ||
    !Array.isArray(value.labels) ||
    value.labels.length > MAX_RECORDS
  ) {
    throw new TypeError("invalid private-label document");
  }

  const aliases = new Set();
  const labels = [];

  for (const record of value.labels) {
    if (
      !plainObject(record) ||
      !exactKeys(record, ["alias", "label"]) ||
      !validAlias(record.alias) ||
      typeof record.label !== "string" ||
      aliases.has(record.alias)
    ) {
      throw new TypeError("invalid private-label document");
    }

    const label = normalizePrivateLabel(record.label);

    if (label.length === 0) {
      throw new TypeError("invalid private-label document");
    }

    aliases.add(record.alias);

    labels.push(
      Object.freeze({
        alias: record.alias,
        label
      })
    );
  }

  return Object.freeze({
    version: 1,
    labels: Object.freeze(labels)
  });
};

const serializedDocument = (labels) =>
  JSON.stringify({
    version: 1,
    labels: [...labels]
      .sort((left, right) =>
        left.alias.localeCompare(right.alias)
      )
      .map(({ alias, label }) => ({
        alias,
        label
      }))
  });

const usableStorage = (storage) =>
  Boolean(storage) &&
  typeof storage.getItem === "function" &&
  typeof storage.setItem === "function" &&
  typeof storage.removeItem === "function";

const unavailableStore = Object.freeze({
  read: () => null,
  write: () => false,
  remove: () => false,
  clearViewer: () => false
});

export function createPrivateLabelStore(storage) {
  if (!usableStorage(storage)) {
    return unavailableStore;
  }

  const readDocument = (subject) =>
    parseDocument(
      storage.getItem(storageKey(subject))
    );

  const read = ({ subject, alias } = {}) => {
    if (
      !validSubject(subject) ||
      !validAlias(alias)
    ) {
      return null;
    }

    try {
      const document = readDocument(subject);
      return (
        document.labels.find(
          (record) => record.alias === alias
        )?.label ?? null
      );
    } catch {
      return null;
    }
  };

  const write = ({
    subject,
    alias,
    label
  } = {}) => {
    if (
      !validSubject(subject) ||
      !validAlias(alias)
    ) {
      return false;
    }

    let normalized;

    try {
      normalized = normalizePrivateLabel(label);
    } catch {
      return false;
    }

    if (normalized.length === 0) {
      return remove({ subject, alias });
    }

    try {
      const document = readDocument(subject);

      const labels = document.labels
        .filter((record) => record.alias !== alias)
        .map((record) => ({
          alias: record.alias,
          label: record.label
        }));

      labels.push({
        alias,
        label: normalized
      });

      if (labels.length > MAX_RECORDS) {
        return false;
      }

      const serialized = serializedDocument(labels);

      if (
        serialized.length >
        MAX_DOCUMENT_CHARACTERS
      ) {
        return false;
      }

      storage.setItem(
        storageKey(subject),
        serialized
      );

      return true;
    } catch {
      return false;
    }
  };

  const remove = ({
    subject,
    alias
  } = {}) => {
    if (
      !validSubject(subject) ||
      !validAlias(alias)
    ) {
      return false;
    }

    try {
      const document = readDocument(subject);

      const labels = document.labels.filter(
        (record) => record.alias !== alias
      );

      if (
        labels.length ===
        document.labels.length
      ) {
        return true;
      }

      if (labels.length === 0) {
        storage.removeItem(
          storageKey(subject)
        );
        return true;
      }

      storage.setItem(
        storageKey(subject),
        serializedDocument(labels)
      );

      return true;
    } catch {
      return false;
    }
  };

  const clearViewer = ({
    subject
  } = {}) => {
    if (!validSubject(subject)) {
      return false;
    }

    try {
      storage.removeItem(
        storageKey(subject)
      );
      return true;
    } catch {
      return false;
    }
  };

  return Object.freeze({
    read,
    write,
    remove,
    clearViewer
  });
}

export function createBrowserPrivateLabelStore(
  browser = globalThis.window
) {
  let storage = null;

  try {
    storage = browser?.localStorage ?? null;
  } catch {
    return unavailableStore;
  }

  return createPrivateLabelStore(storage);
}
