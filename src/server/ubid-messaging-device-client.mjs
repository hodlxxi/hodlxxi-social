import http from "node:http";
import {
  createPrivateKey,
  randomBytes,
  sign
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open as openFile } from "node:fs/promises";

export const MESSAGING_DEVICE_SCOPE =
  "social:messaging-device:manage";

export const UBID_MESSAGING_SERVICE_TOKEN_PATH =
  "/internal/v1/social/messaging/service-token";

export const UBID_MESSAGING_DEVICE_BINDINGS_PATH =
  "/internal/v1/social/messaging/device-bindings";

const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const GRANT_TYPE = "client_credentials";
const ASSERTION_TOKEN_USE = "client_assertion";
const ASSERTION_PURPOSE = "service_client_authentication";

const COMMAND_MAX_BYTES = 8192;
const TOKEN_MAX_BYTES = 16 * 1024;
const DEVICE_MAX_BYTES = 128 * 1024;
const PRIVATE_KEY_MAX_BYTES = 32 * 1024;

const HEX64 = /^[0-9a-f]{64}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const ISO_UTC_SECOND =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const failure = () => {
  throw new Error("messaging_device_unavailable");
};

const boundedText = (value, maximum) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= maximum &&
  !/[\u0000-\u001f\u007f]/.test(value);

const boundedBearer = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 8192 &&
  !/[\u0000-\u0020\u007f]/.test(value);

const exactRecord = (value, fields) => {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) failure();

    const descriptors =
      Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);

    if (
      keys.length !== fields.length ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          !fields.includes(key) ||
          !descriptors[key].enumerable ||
          !Object.hasOwn(descriptors[key], "value")
      ) ||
      fields.some((field) => !keys.includes(field))
    ) failure();

    return Object.fromEntries(
      fields.map(
        (field) => [field, descriptors[field].value]
      )
    );
  } catch {
    failure();
  }
};

const canonicalHttpsEndpoint = (
  value,
  expectedPath
) => {
  try {
    if (typeof value !== "string") failure();

    const url = new URL(value);

    if (
      url.href !== value ||
      url.protocol !== "https:" ||
      !url.hostname ||
      url.hostname.endsWith(".") ||
      url.username ||
      url.password ||
      url.pathname !== expectedPath ||
      url.search ||
      url.hash
    ) failure();

    return Object.freeze({
      href: url.href,
      host: url.host,
      path: url.pathname
    });
  } catch {
    failure();
  }
};

const base64urlJson = (value) =>
  Buffer.from(
    JSON.stringify(value),
    "utf8"
  ).toString("base64url");

const validConfig = (config) =>
  config?.enabled === true &&
  boundedText(config.socketPath, 107) &&
  boundedText(config.clientId, 256) &&
  boundedText(config.clientSigningKeyId, 255) &&
  boundedText(config.tokenEndpointAudience, 2048) &&
  boundedText(config.signingKeyPath, 2048) &&
  Number.isSafeInteger(config.tokenTimeoutMs) &&
  config.tokenTimeoutMs >= 250 &&
  config.tokenTimeoutMs <= 30000 &&
  Number.isSafeInteger(config.requestTimeoutMs) &&
  config.requestTimeoutMs >= 250 &&
  config.requestTimeoutMs <= 30000;

const createClientAssertion = (
  config,
  privateKey,
  {
    now = Date.now,
    random = randomBytes,
    signImpl = sign
  } = {}
) => {
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

  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: config.clientSigningKeyId
  };

  const claims = {
    iss: config.clientId,
    sub: config.clientId,
    aud: config.tokenEndpointAudience,
    token_use: ASSERTION_TOKEN_USE,
    grant_type: GRANT_TYPE,
    purpose: ASSERTION_PURPOSE,
    iat: issuedAt,
    exp: issuedAt + 60,
    jti: Buffer.from(entropy).toString("base64url")
  };

  const signingInput =
    `${base64urlJson(header)}.${base64urlJson(claims)}`;

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

  if (
    !(signature instanceof Uint8Array) ||
    signature.byteLength === 0
  ) failure();

  return (
    signingInput +
    "." +
    Buffer.from(signature).toString("base64url")
  );
};

const rejectDuplicateJsonMembers = (source) => {
  let offset = 0;

  const whitespace = () => {
    while (/\s/.test(source[offset] ?? "")) {
      offset += 1;
    }
  };

  const string = () => {
    const start = offset++;
    let escaped = false;

    while (offset < source.length) {
      const character = source[offset++];

      if (!escaped && character === '"') {
        return JSON.parse(
          source.slice(start, offset)
        );
      }

      escaped =
        !escaped && character === "\\";
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

    while (
      offset < source.length &&
      !/[\s,}\]]/.test(source[offset])
    ) {
      offset += 1;
    }

    if (start === offset) failure();
  };

  whitespace();
  walk();
  whitespace();

  if (offset !== source.length) failure();
};

const parseJson = (source) => {
  try {
    rejectDuplicateJsonMembers(source);
    return JSON.parse(source);
  } catch {
    failure();
  }
};

const unixJsonRequest = (
  {
    socketPath,
    endpoint,
    method,
    headers,
    body,
    timeoutMs,
    maximumBytes
  },
  requestImpl
) =>
  new Promise((resolve, reject) => {
    let settled = false;
    let request;
    let response;

    const rejectUnavailable = () => {
      try { request?.destroy(); } catch {}
      try { response?.destroy(); } catch {}

      if (settled) return;
      settled = true;
      reject(new Error("messaging_device_unavailable"));
    };

    const outgoingHeaders = {
      ...headers,
      Host: endpoint.host
    };

    if (body !== undefined) {
      outgoingHeaders["Content-Length"] =
        String(Buffer.byteLength(body, "utf8"));
    }

    try {
      request = requestImpl(
        {
          socketPath,
          path: endpoint.path,
          method,
          headers: outgoingHeaders,
          setHost: false,
          maxHeaderSize: 16 * 1024
        },
        (incoming) => {
          response = incoming;

          if (
            !incoming ||
            incoming.statusCode !== 200
          ) {
            rejectUnavailable();
            return;
          }

          const contentType =
            incoming.headers?.["content-type"];

          if (
            typeof contentType !== "string" ||
            !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(
              contentType
            )
          ) {
            rejectUnavailable();
            return;
          }

          const chunks = [];
          let length = 0;

          incoming.on("data", (chunk) => {
            if (settled) return;

            if (!(chunk instanceof Uint8Array)) {
              rejectUnavailable();
              return;
            }

            length += chunk.byteLength;

            if (length > maximumBytes) {
              rejectUnavailable();
              return;
            }

            chunks.push(Buffer.from(chunk));
          });

          incoming.once("error", rejectUnavailable);

          incoming.once("end", () => {
            if (settled) return;

            try {
              const source =
                Buffer.concat(chunks, length)
                  .toString("utf8");

              const value = parseJson(source);

              settled = true;
              resolve(value);
            } catch {
              rejectUnavailable();
            }
          });
        }
      );

      request.once("error", rejectUnavailable);

      request.setTimeout(
        timeoutMs,
        rejectUnavailable
      );

      request.end(body);
    } catch {
      rejectUnavailable();
    }
  });

const readPrivateKey = async (
  path,
  {
    openFileImpl = openFile,
    createPrivateKeyImpl = createPrivateKey
  } = {}
) => {
  let handle;

  try {
    const noFollow = fsConstants.O_NOFOLLOW;

    if (
      !Number.isSafeInteger(noFollow) ||
      noFollow <= 0
    ) failure();

    const closeOnExec =
      Number.isSafeInteger(fsConstants.O_CLOEXEC)
        ? fsConstants.O_CLOEXEC
        : 0;

    handle = await openFileImpl(
      path,
      fsConstants.O_RDONLY |
        noFollow |
        closeOnExec
    );

    const info = await handle.stat();

    if (
      !info.isFile() ||
      (info.mode & 0o077) !== 0 ||
      info.size <= 0 ||
      info.size > PRIVATE_KEY_MAX_BYTES
    ) failure();

    const source =
      await handle.readFile({
        encoding: "utf8"
      });

    const key =
      createPrivateKeyImpl(source);

    if (
      key?.type !== "private" ||
      key?.asymmetricKeyType !== "rsa" ||
      !Number.isSafeInteger(
        key.asymmetricKeyDetails?.modulusLength
      ) ||
      key.asymmetricKeyDetails.modulusLength < 2048
    ) failure();

    return key;
  } catch {
    failure();
  } finally {
    try { await handle?.close(); } catch {}
  }
};

const validateServiceToken = (value) => {
  const result = exactRecord(
    value,
    [
      "access_token",
      "token_type",
      "expires_in",
      "scope"
    ]
  );

  if (
    !boundedBearer(result.access_token) ||
    result.token_type !== "Bearer" ||
    result.expires_in !== 60 ||
    result.scope !== MESSAGING_DEVICE_SCOPE
  ) failure();

  return result.access_token;
};

const normalizeDevice = (
  value,
  {
    snapshot = false
  } = {}
) => {
  const fields = snapshot
    ? [
        "snapshotId",
        "deviceId",
        "bindingId",
        "algorithm",
        "version",
        "publicKey",
        "validFrom",
        "expiresAt",
        "revoked"
      ]
    : [
        "deviceId",
        "bindingId",
        "algorithm",
        "version",
        "publicKey",
        "validFrom",
        "expiresAt"
      ];

  const record = exactRecord(value, fields);

  if (
    !HEX64.test(record.deviceId) ||
    !HEX64.test(record.bindingId) ||
    record.algorithm !== "x25519-v1" ||
    !Number.isSafeInteger(record.version) ||
    record.version < 1 ||
    record.version > 1024 ||
    !HEX64.test(record.publicKey)
  ) failure();

  if (snapshot) {
    if (
      !SNAPSHOT_ID.test(record.snapshotId) ||
      !Number.isSafeInteger(record.validFrom) ||
      !Number.isSafeInteger(record.expiresAt) ||
      record.validFrom < 0 ||
      record.expiresAt <= record.validFrom ||
      record.revoked !== false
    ) failure();
  } else if (
    !ISO_UTC_SECOND.test(record.validFrom) ||
    !ISO_UTC_SECOND.test(record.expiresAt)
  ) {
    failure();
  }

  return Object.freeze({ ...record });
};

export function normalizeMessagingDeviceSnapshot(
  value
) {
  const record = exactRecord(
    value,
    [
      "schema",
      "version",
      "source",
      "snapshotId",
      "complete",
      "issuedAt",
      "expiresAt",
      "activeDevices"
    ]
  );

  if (
    record.schema !==
      "hodlxxi.social_messaging_device_binding_snapshot.v1" ||
    record.version !== 1 ||
    record.source !== "hodlxxi-ubid" ||
    !SNAPSHOT_ID.test(record.snapshotId) ||
    record.complete !== true ||
    !Number.isSafeInteger(record.issuedAt) ||
    !Number.isSafeInteger(record.expiresAt) ||
    record.issuedAt < 0 ||
    record.expiresAt <= record.issuedAt ||
    !Array.isArray(record.activeDevices) ||
    record.activeDevices.length > 16
  ) failure();

  const devices = [];
  const ids = new Set();
  const keys = new Set();

  for (const raw of record.activeDevices) {
    const device =
      normalizeDevice(raw, { snapshot: true });

    if (
      device.snapshotId !== record.snapshotId ||
      ids.has(device.deviceId) ||
      keys.has(device.publicKey)
    ) failure();

    ids.add(device.deviceId);
    keys.add(device.publicKey);
    devices.push(device);
  }

  return Object.freeze({
    schema: record.schema,
    version: 1,
    source: record.source,
    snapshotId: record.snapshotId,
    complete: true,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    activeDevices: Object.freeze(devices)
  });
}

export function normalizeMessagingDeviceResult(
  value
) {
  const record = exactRecord(
    value,
    [
      "schema",
      "version",
      "operation",
      "device"
    ]
  );

  if (
    record.schema !==
      "hodlxxi.social_messaging_device_binding_result.v1" ||
    record.version !== 1 ||
    !["register", "rotate", "revoke"].includes(
      record.operation
    )
  ) failure();

  return Object.freeze({
    schema: record.schema,
    version: 1,
    operation: record.operation,
    device: normalizeDevice(record.device)
  });
}

export async function createUbidMessagingDeviceClient(
  config,
  {
    requestImpl = http.request,
    openFileImpl = openFile,
    createPrivateKeyImpl = createPrivateKey,
    now = Date.now,
    random = randomBytes,
    signImpl = sign
  } = {}
) {
  if (
    !validConfig(config) ||
    typeof requestImpl !== "function"
  ) failure();

  const tokenEndpoint =
    canonicalHttpsEndpoint(
      config.serviceTokenUrl,
      UBID_MESSAGING_SERVICE_TOKEN_PATH
    );

  const deviceEndpoint =
    canonicalHttpsEndpoint(
      config.deviceBindingsUrl,
      UBID_MESSAGING_DEVICE_BINDINGS_PATH
    );

  const privateKey =
    await readPrivateKey(
      config.signingKeyPath,
      {
        openFileImpl,
        createPrivateKeyImpl
      }
    );

  const serviceToken = async () => {
    const assertion =
      createClientAssertion(
        config,
        privateKey,
        {
          now,
          random,
          signImpl
        }
      );

    const body =
      new URLSearchParams([
        ["grant_type", GRANT_TYPE],
        ["client_id", config.clientId],
        ["scope", MESSAGING_DEVICE_SCOPE],
        ["client_assertion_type", CLIENT_ASSERTION_TYPE],
        ["client_assertion", assertion]
      ]).toString();

    const value =
      await unixJsonRequest(
        {
          socketPath: config.socketPath,
          endpoint: tokenEndpoint,
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type":
              "application/x-www-form-urlencoded"
          },
          body,
          timeoutMs: config.tokenTimeoutMs,
          maximumBytes: TOKEN_MAX_BYTES
        },
        requestImpl
      );

    return validateServiceToken(value);
  };

  return Object.freeze({
    async currentForViewer(
      {
        viewerAccessToken
      } = {}
    ) {
      if (!boundedBearer(viewerAccessToken)) {
        failure();
      }

      const token = await serviceToken();

      if (token === viewerAccessToken) failure();

      const value =
        await unixJsonRequest(
          {
            socketPath: config.socketPath,
            endpoint: deviceEndpoint,
            method: "GET",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${token}`,
              "X-HODLXXI-Viewer-Authorization":
                `Bearer ${viewerAccessToken}`
            },
            timeoutMs: config.requestTimeoutMs,
            maximumBytes: DEVICE_MAX_BYTES
          },
          requestImpl
        );

      return normalizeMessagingDeviceSnapshot(
        value
      );
    },

    async applyForViewer(
      {
        viewerAccessToken,
        commandPayload
      } = {}
    ) {
      if (
        !boundedBearer(viewerAccessToken) ||
        typeof commandPayload !== "string" ||
        Buffer.byteLength(commandPayload, "utf8") < 1 ||
        Buffer.byteLength(commandPayload, "utf8") >
          COMMAND_MAX_BYTES ||
        /[^\x20-\x7e]/.test(commandPayload)
      ) failure();

      const token = await serviceToken();

      if (token === viewerAccessToken) failure();

      const value =
        await unixJsonRequest(
          {
            socketPath: config.socketPath,
            endpoint: deviceEndpoint,
            method: "POST",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${token}`,
              "X-HODLXXI-Viewer-Authorization":
                `Bearer ${viewerAccessToken}`,
              "Content-Type": "application/json"
            },
            body: commandPayload,
            timeoutMs: config.requestTimeoutMs,
            maximumBytes: DEVICE_MAX_BYTES
          },
          requestImpl
        );

      return normalizeMessagingDeviceResult(
        value
      );
    }
  });
}
