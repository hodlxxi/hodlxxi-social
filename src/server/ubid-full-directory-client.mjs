import {
  createPrivateKey,
  randomBytes,
  sign
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open as openFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

export const FULL_DIRECTORY_SCOPE = "social:full-directory:read";
export const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const CLIENT_ASSERTION_TOKEN_USE = "client_assertion";
export const CLIENT_ASSERTION_GRANT_TYPE = "client_credentials";
export const CLIENT_ASSERTION_PURPOSE =
  "service_client_authentication";
export const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;
export const SERVICE_TOKEN_LIFETIME_SECONDS = 60;
export const UBID_FULL_DIRECTORY_SCHEMA =
  "hodlxxi.privacy_safe_full_directory.v1";
export const UBID_FULL_DIRECTORY_VERSION = 1;
export const MAX_PRIVACY_SAFE_PARTICIPANTS = 4096;

const MAX_TOKEN_RESPONSE_BYTES = 16 * 1024;
const MAX_DIRECTORY_RESPONSE_BYTES = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES = 32 * 1024;
const MAX_CLIENT_SIGNING_KEY_ID_LENGTH = 255;
const JSON_CONTENT_TYPE =
  /^application\/json(?:[\t ]*;[\t ]*charset[\t ]*=[\t ]*(?:utf-8|"utf-8"))?[\t ]*$/i;
const RAW_IDENTITY_KEY = /^[0-9a-f]{64}$/i;
const IDENTITY_OR_WALLET_PREFIX = /^(?:npub1|nprofile1|nsec1|xpub|tpub|ypub|zpub|vpub|xprv|tprv|yprv|zprv|vprv|bc1|tb1)/i;
const BITCOIN_BASE58_ADDRESS = /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const PHONE_LIKE = /^\d{7,15}$/;

const failure = () => {
  throw new Error("full_directory_unavailable");
};

const plainRecord = (value, fields) => {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.length !== fields.length ||
      keys.some((key) => typeof key !== "string" || !fields.includes(key)) ||
      fields.some((field) => !keys.includes(field)) ||
      keys.some((key) =>
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value")
      )
    ) return undefined;
    return Object.fromEntries(
      fields.map((field) => [field, descriptors[field].value])
    );
  } catch {
    return undefined;
  }
};

const denseArray = (value) => {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      return undefined;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length?.value;
    const keys = Reflect.ownKeys(descriptors);
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > MAX_PRIVACY_SAFE_PARTICIPANTS ||
      keys.length !== length + 1
    ) return undefined;
    const items = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) return undefined;
      items.push(descriptor.value);
    }
    if (
      keys.some((key) =>
        key !== "length" &&
        !(typeof key === "string" && /^(0|[1-9]\d*)$/.test(key))
      )
    ) return undefined;
    return items;
  } catch {
    return undefined;
  }
};

const boundedBearer = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 8192 &&
  !/[\u0000-\u0020\u007f]/.test(value);

const boundedText = (value, maximum) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= maximum &&
  !/[\u0000-\u001f\u007f]/.test(value);

const exactCredentialString = (value, maximum) =>
  boundedText(value, maximum) && value.trim() === value;

const canonicalHttpsUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" &&
      url.hostname &&
      !url.hostname.endsWith(".") &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.href === value;
  } catch {
    return false;
  }
};

const validConfig = (config) =>
  config?.enabled === true &&
  canonicalHttpsUrl(config.serviceTokenUrl) &&
  canonicalHttpsUrl(config.directoryUrl) &&
  exactCredentialString(config.clientId, 256) &&
  exactCredentialString(
    config.clientSigningKeyId,
    MAX_CLIENT_SIGNING_KEY_ID_LENGTH
  ) &&
  exactCredentialString(config.tokenEndpointAudience, 2048) &&
  boundedText(config.signingKeyPath, 2048) &&
  isAbsolute(config.signingKeyPath) &&
  Number.isSafeInteger(config.tokenTimeoutMs) &&
  config.tokenTimeoutMs >= 250 &&
  config.tokenTimeoutMs <= 30000 &&
  Number.isSafeInteger(config.requestTimeoutMs) &&
  config.requestTimeoutMs >= 250 &&
  config.requestTimeoutMs <= 30000;

const privacySafeAlias = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9._~-]{1,128}$/.test(value) &&
  !RAW_IDENTITY_KEY.test(value) &&
  !IDENTITY_OR_WALLET_PREFIX.test(value) &&
  !BITCOIN_BASE58_ADDRESS.test(value) &&
  !PHONE_LIKE.test(value) &&
  !value.includes("@");

const base64urlJson = (value) =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

export function createClientAssertion(
  config,
  privateKey,
  {
    now = Date.now,
    random = randomBytes,
    signImpl = sign
  } = {}
) {
  if (
    !validConfig(config) ||
    typeof now !== "function" ||
    typeof random !== "function" ||
    typeof signImpl !== "function"
  ) failure();

  const issuedAt = Math.floor(now() / 1000);
  const entropy = random(32);
  if (
    !Number.isSafeInteger(issuedAt) ||
    issuedAt < 0 ||
    !(entropy instanceof Uint8Array) ||
    entropy.byteLength !== 32
  ) failure();

  const header = Object.freeze({
    alg: "RS256",
    typ: "JWT",
    kid: config.clientSigningKeyId
  });
  const claims = Object.freeze({
    iss: config.clientId,
    sub: config.clientId,
    aud: config.tokenEndpointAudience,
    token_use: CLIENT_ASSERTION_TOKEN_USE,
    grant_type: CLIENT_ASSERTION_GRANT_TYPE,
    purpose: CLIENT_ASSERTION_PURPOSE,
    iat: issuedAt,
    exp: issuedAt + CLIENT_ASSERTION_LIFETIME_SECONDS,
    jti: Buffer.from(entropy).toString("base64url")
  });
  const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;
  let signature;
  try {
    signature = signImpl(
      "RSA-SHA256",
      Buffer.from(signingInput, "ascii"),
      privateKey
    );
  } catch {
    failure();
  }
  if (!(signature instanceof Uint8Array) || signature.byteLength === 0) {
    failure();
  }
  return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
}

export function validateServiceTokenResponse(value) {
  const record = plainRecord(value, [
    "access_token",
    "token_type",
    "expires_in",
    "scope"
  ]);
  if (
    !record ||
    !boundedBearer(record.access_token) ||
    record.token_type !== "Bearer" ||
    record.scope !== FULL_DIRECTORY_SCOPE ||
    !Number.isSafeInteger(record.expires_in) ||
    record.expires_in !== SERVICE_TOKEN_LIFETIME_SECONDS
  ) failure();
  return record.access_token;
}

export function normalizeUbidFullDirectory(value) {
  const document = plainRecord(value, ["schema", "version", "participants"]);
  const rawParticipants = denseArray(document?.participants);
  if (
    !document ||
    document.schema !== UBID_FULL_DIRECTORY_SCHEMA ||
    document.version !== UBID_FULL_DIRECTORY_VERSION ||
    !rawParticipants
  ) failure();

  const aliases = [];
  const seen = new Set();
  for (const valueParticipant of rawParticipants) {
    const participant = plainRecord(valueParticipant, [
      "alias",
      "identity_class",
      "current_full_relation_satisfied"
    ]);
    if (
      !participant ||
      !privacySafeAlias(participant.alias) ||
      participant.identity_class !== "full" ||
      participant.current_full_relation_satisfied !== true ||
      seen.has(participant.alias)
    ) failure();
    seen.add(participant.alias);
    aliases.push(Object.freeze({ alias: participant.alias }));
  }

  return Object.freeze({
    state: "available",
    participants: Object.freeze(aliases)
  });
}

const rejectDuplicateJsonMembers = (source) => {
  let offset = 0;
  const whitespace = () => {
    while (/\s/.test(source[offset] ?? "")) offset += 1;
  };
  const string = () => {
    const start = offset++;
    let escaped = false;
    while (offset < source.length) {
      const character = source[offset++];
      if (!escaped && character === '"') {
        return JSON.parse(source.slice(start, offset));
      }
      escaped = !escaped && character === "\\";
    }
    failure();
  };
  const walk = () => {
    whitespace();
    if (source[offset] === '"') {
      string();
      return;
    }
    if (source[offset] === "{") {
      offset += 1;
      whitespace();
      const names = new Set();
      if (source[offset] === "}") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        if (source[offset] !== '"') failure();
        const name = string();
        if (names.has(name)) failure();
        names.add(name);
        whitespace();
        if (source[offset++] !== ":") failure();
        walk();
        whitespace();
        const separator = source[offset++];
        if (separator === "}") return;
        if (separator !== ",") failure();
        whitespace();
      }
      failure();
    }
    if (source[offset] === "[") {
      offset += 1;
      whitespace();
      if (source[offset] === "]") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        walk();
        whitespace();
        const separator = source[offset++];
        if (separator === "]") return;
        if (separator !== ",") failure();
        whitespace();
      }
      failure();
    }
    const start = offset;
    while (offset < source.length && !/[\s,}\]]/.test(source[offset])) {
      offset += 1;
    }
    if (start === offset) failure();
  };
  whitespace();
  walk();
  whitespace();
  if (offset !== source.length) failure();
};

const cancelResponse = (response) => {
  try {
    const cancellation = response?.body?.cancel?.();
    Promise.resolve(cancellation).catch(() => {});
  } catch {}
};

const readJson = async (
  url,
  init,
  {
    fetchImpl,
    timeoutMs,
    maximumBytes,
    setTimeoutImpl,
    clearTimeoutImpl
  }
) => {
  const controller = new AbortController();
  const timer = setTimeoutImpl(() => controller.abort(), timeoutMs);
  let response;
  let accepted = false;
  try {
    response = await fetchImpl(url, {
      ...init,
      credentials: "omit",
      redirect: "error",
      signal: controller.signal
    });
    if (!response || response.status !== 200) failure();
    const contentType = response.headers?.get?.("content-type");
    const declared = response.headers?.get?.("content-length");
    if (
      typeof contentType !== "string" ||
      !JSON_CONTENT_TYPE.test(contentType) ||
      (
        declared !== null &&
        declared !== undefined &&
        (
          typeof declared !== "string" ||
          !/^[0-9]+$/.test(declared) ||
          Number(declared) > maximumBytes
        )
      ) ||
      !response.body ||
      typeof response.body.getReader !== "function"
    ) failure();
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) failure();
        length += value.byteLength;
        if (length > maximumBytes) failure();
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(length);
    let cursor = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, cursor);
      cursor += chunk.byteLength;
    }
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      failure();
    }
    rejectDuplicateJsonMembers(source);
    let value;
    try {
      value = JSON.parse(source);
    } catch {
      failure();
    }
    accepted = true;
    return value;
  } catch {
    failure();
  } finally {
    if (!accepted) {
      controller.abort();
      cancelResponse(response);
    }
    try { clearTimeoutImpl(timer); } catch {}
  }
};

const readPrivateKeyFile = async (path, openFileImpl) => {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (!Number.isSafeInteger(noFollow) || noFollow <= 0) failure();
  const closeOnExec = Number.isSafeInteger(fsConstants.O_CLOEXEC)
    ? fsConstants.O_CLOEXEC
    : 0;
  const flags = fsConstants.O_RDONLY | noFollow | closeOnExec;
  let handle;
  let source;
  let failed = false;
  try {
    handle = await openFileImpl(path, flags);
    if (
      !handle ||
      typeof handle.stat !== "function" ||
      typeof handle.read !== "function" ||
      typeof handle.close !== "function"
    ) failure();
    const info = await handle.stat();
    if (
      !info ||
      typeof info.isFile !== "function" ||
      info.isFile() !== true ||
      !Number.isSafeInteger(info.mode) ||
      (info.mode & 0o077) !== 0 ||
      !Number.isSafeInteger(info.size) ||
      info.size <= 0 ||
      info.size > MAX_PRIVATE_KEY_FILE_BYTES
    ) failure();

    const bytes = Buffer.alloc(MAX_PRIVATE_KEY_FILE_BYTES + 1);
    let length = 0;
    while (length < bytes.byteLength) {
      const result = await handle.read(
        bytes,
        length,
        bytes.byteLength - length,
        null
      );
      if (
        !result ||
        !Number.isSafeInteger(result.bytesRead) ||
        result.bytesRead < 0 ||
        result.bytesRead > bytes.byteLength - length
      ) failure();
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length === 0 || length > MAX_PRIVATE_KEY_FILE_BYTES) failure();
    try {
      source = new TextDecoder("utf-8", { fatal: true })
        .decode(bytes.subarray(0, length));
    } catch {
      failure();
    }
  } catch {
    failed = true;
  }
  if (handle) {
    try {
      await handle.close();
    } catch {
      failed = true;
    }
  }
  if (failed || typeof source !== "string" || source.length === 0) {
    failure();
  }
  return source;
};

export async function createUbidFullDirectoryClient(
  config,
  {
    fetchImpl = globalThis.fetch,
    openFileImpl = openFile,
    createPrivateKeyImpl = createPrivateKey,
    now = Date.now,
    random = randomBytes,
    signImpl = sign,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout
  } = {}
) {
  if (
    !validConfig(config) ||
    typeof fetchImpl !== "function" ||
    typeof openFileImpl !== "function" ||
    typeof createPrivateKeyImpl !== "function"
  ) failure();

  let privateKey;
  try {
    const source = await readPrivateKeyFile(
      config.signingKeyPath,
      openFileImpl
    );
    privateKey = createPrivateKeyImpl(source);
    if (
      privateKey?.type !== "private" ||
      privateKey?.asymmetricKeyType !== "rsa" ||
      !Number.isSafeInteger(
        privateKey.asymmetricKeyDetails?.modulusLength
      ) ||
      privateKey.asymmetricKeyDetails.modulusLength < 2048
    ) failure();
  } catch {
    failure();
  }

  return Object.freeze({
    async readForViewer({ viewerAccessToken } = {}) {
      if (!boundedBearer(viewerAccessToken)) failure();
      const assertion = createClientAssertion(config, privateKey, {
        now,
        random,
        signImpl
      });
      const form = new URLSearchParams([
        ["grant_type", CLIENT_ASSERTION_GRANT_TYPE],
        ["client_id", config.clientId],
        ["scope", FULL_DIRECTORY_SCOPE],
        ["client_assertion_type", CLIENT_ASSERTION_TYPE],
        ["client_assertion", assertion]
      ]).toString();
      const serviceTokenDocument = await readJson(
        config.serviceTokenUrl,
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: form
        },
        {
          fetchImpl,
          timeoutMs: config.tokenTimeoutMs,
          maximumBytes: MAX_TOKEN_RESPONSE_BYTES,
          setTimeoutImpl,
          clearTimeoutImpl
        }
      );
      const serviceToken = validateServiceTokenResponse(
        serviceTokenDocument
      );
      if (serviceToken === viewerAccessToken) failure();
      const directoryDocument = await readJson(
        config.directoryUrl,
        {
          method: "GET",
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${serviceToken}`,
            "X-HODLXXI-Viewer-Authorization":
              `Bearer ${viewerAccessToken}`
          }
        },
        {
          fetchImpl,
          timeoutMs: config.requestTimeoutMs,
          maximumBytes: MAX_DIRECTORY_RESPONSE_BYTES,
          setTimeoutImpl,
          clearTimeoutImpl
        }
      );
      return normalizeUbidFullDirectory(directoryDocument);
    }
  });
}
