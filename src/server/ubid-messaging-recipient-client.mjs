import http from "node:http";
import {
  createHash,
  createPrivateKey,
  randomBytes,
  sign
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open as openFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import {
  canonicalUnixSocketPath
} from "./social-oauth-config.mjs";

export const MESSAGING_RECIPIENT_SCOPE =
  "social:messaging-recipient:read";

export const UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH =
  "/internal/v1/social/messaging/recipient-service-token";

export const UBID_MESSAGING_RECIPIENT_DEVICES_PATH =
  "/internal/v1/social/messaging/recipient-devices";

export const MESSAGING_RECIPIENT_PACKAGE_SCHEMA =
  "hodlxxi.social_messaging_recipient_package.v1";

const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const GRANT_TYPE = "client_credentials";
const ASSERTION_TOKEN_USE = "client_assertion";
const ASSERTION_PURPOSE = "service_client_authentication";

const TOKEN_MAX_BYTES = 16 * 1024;
const PACKAGE_MAX_BYTES = 128 * 1024;
const PRIVATE_KEY_MAX_BYTES = 32 * 1024;

const ALIAS = /^p_[A-Za-z0-9_-]{22}$/;
const DEVICE_HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_ACTIVE_DEVICES = 16;
const MAX_BINDING_VERSION = 1024;
const SOURCE = "hodlxxi-ubid";
const VERSION = 1;
const ALGORITHM = "x25519-v1";
const X25519_FIELD_PRIME =
  (1n << 255n) - 19n;
const PROHIBITED_X25519 =
  new Set([
    "00".repeat(32),
    "01" + "00".repeat(31),
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900",
    "ec" + "ff".repeat(30) + "7f",
    "ed" + "ff".repeat(30) + "7f",
    "ee" + "ff".repeat(30) + "7f"
  ]);

const failure = () => {
  throw new Error("messaging_recipient_unavailable");
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
        (field) => [
          field,
          descriptors[field].value
        ]
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

const validConfig = (config) => {
  try {
    return (
      config?.enabled === true &&
      canonicalUnixSocketPath(
        config.socketPath
      ) === config.socketPath &&
      boundedText(config.clientId, 256) &&
      boundedText(
        config.clientSigningKeyId,
        255
      ) &&
      boundedText(
        config.tokenEndpointAudience,
        2048
      ) &&
      boundedText(
        config.signingKeyPath,
        2048
      ) &&
      isAbsolute(
        config.signingKeyPath
      ) &&
      Number.isSafeInteger(
        config.tokenTimeoutMs
      ) &&
      config.tokenTimeoutMs >= 250 &&
      config.tokenTimeoutMs <= 30000 &&
      Number.isSafeInteger(
        config.requestTimeoutMs
      ) &&
      config.requestTimeoutMs >= 250 &&
      config.requestTimeoutMs <= 30000
    );
  } catch {
    return false;
  }
};

const base64urlJson = (value) =>
  Buffer.from(
    JSON.stringify(value),
    "utf8"
  ).toString("base64url");

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

  const issuedAt =
    Math.floor(now() / 1000);
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
    jti:
      Buffer.from(entropy)
        .toString("base64url")
  };

  const signingInput =
    `${base64urlJson(header)}.${base64urlJson(claims)}`;

  let signature;

  try {
    signature = signImpl(
      "RSA-SHA256",
      Buffer.from(
        signingInput,
        "ascii"
      ),
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
    Buffer.from(signature)
      .toString("base64url")
  );
};

const rejectDuplicateJsonMembers = (
  source
) => {
  let offset = 0;

  const whitespace = () => {
    while (
      /\s/.test(
        source[offset] ?? ""
      )
    ) {
      offset += 1;
    }
  };

  const string = () => {
    const start = offset++;
    let escaped = false;

    while (offset < source.length) {
      const character =
        source[offset++];

      if (
        !escaped &&
        character === '"'
      ) {
        return JSON.parse(
          source.slice(
            start,
            offset
          )
        );
      }

      escaped =
        !escaped &&
        character === "\\";
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

      while (
        offset < source.length
      ) {
        if (
          source[offset] !== '"'
        ) failure();

        const name = string();

        if (names.has(name)) {
          failure();
        }
        names.add(name);

        whitespace();

        if (
          source[offset++] !== ":"
        ) failure();

        walk();
        whitespace();

        const separator =
          source[offset++];

        if (separator === "}") {
          return;
        }
        if (separator !== ",") {
          failure();
        }

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

      while (
        offset < source.length
      ) {
        walk();
        whitespace();

        const separator =
          source[offset++];

        if (separator === "]") {
          return;
        }
        if (separator !== ",") {
          failure();
        }

        whitespace();
      }

      failure();
    }

    const start = offset;

    while (
      offset < source.length &&
      !/[\s,}\]]/.test(
        source[offset]
      )
    ) {
      offset += 1;
    }

    if (start === offset) {
      failure();
    }
  };

  whitespace();
  walk();
  whitespace();

  if (offset !== source.length) {
    failure();
  }
};

const parseJson = (source) => {
  try {
    rejectDuplicateJsonMembers(
      source
    );
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
  new Promise(
    (resolve, reject) => {
      let settled = false;
      let request;
      let response;

      const rejectUnavailable =
        () => {
          try {
            request?.destroy();
          } catch {}
          try {
            response?.destroy();
          } catch {}

          if (settled) return;
          settled = true;
          reject(
            new Error(
              "messaging_recipient_unavailable"
            )
          );
        };

      const outgoingHeaders = {
        ...headers,
        Host: endpoint.host
      };

      if (body !== undefined) {
        outgoingHeaders[
          "Content-Length"
        ] = String(
          Buffer.byteLength(
            body,
            "utf8"
          )
        );
      }

      try {
        request = requestImpl(
          {
            socketPath,
            path: endpoint.path,
            method,
            headers:
              outgoingHeaders,
            setHost: false,
            maxHeaderSize:
              16 * 1024
          },
          (incoming) => {
            response = incoming;

            if (
              !incoming ||
              incoming.statusCode !==
                200
            ) {
              rejectUnavailable();
              return;
            }

            const contentType =
              incoming.headers?.[
                "content-type"
              ];

            if (
              typeof contentType !==
                "string" ||
              !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(
                contentType
              )
            ) {
              rejectUnavailable();
              return;
            }

            const chunks = [];
            let length = 0;

            incoming.on(
              "data",
              (chunk) => {
                if (settled) return;

                if (
                  !(
                    chunk instanceof
                    Uint8Array
                  )
                ) {
                  rejectUnavailable();
                  return;
                }

                length +=
                  chunk.byteLength;

                if (
                  length >
                  maximumBytes
                ) {
                  rejectUnavailable();
                  return;
                }

                chunks.push(
                  Buffer.from(chunk)
                );
              }
            );

            incoming.once(
              "error",
              rejectUnavailable
            );

            incoming.once(
              "end",
              () => {
                if (settled) return;

                try {
                  const source =
                    Buffer.concat(
                      chunks,
                      length
                    ).toString(
                      "utf8"
                    );

                  const value =
                    parseJson(
                      source
                    );

                  settled = true;
                  resolve(value);
                } catch {
                  rejectUnavailable();
                }
              }
            );
          }
        );

        request.once(
          "error",
          rejectUnavailable
        );

        request.setTimeout(
          timeoutMs,
          rejectUnavailable
        );

        request.end(body);
      } catch {
        rejectUnavailable();
      }
    }
  );

const readPrivateKey = async (
  path,
  {
    openFileImpl = openFile,
    createPrivateKeyImpl =
      createPrivateKey
  } = {}
) => {
  let handle;

  try {
    const noFollow =
      fsConstants.O_NOFOLLOW;

    if (
      !Number.isSafeInteger(
        noFollow
      ) ||
      noFollow <= 0
    ) failure();

    const closeOnExec =
      Number.isSafeInteger(
        fsConstants.O_CLOEXEC
      )
        ? fsConstants.O_CLOEXEC
        : 0;

    handle =
      await openFileImpl(
        path,
        fsConstants.O_RDONLY |
          noFollow |
          closeOnExec
      );

    const info =
      await handle.stat();

    if (
      !info.isFile() ||
      (info.mode & 0o077) !== 0 ||
      info.size <= 0 ||
      info.size >
        PRIVATE_KEY_MAX_BYTES
    ) failure();

    const source =
      await handle.readFile({
        encoding: "utf8"
      });

    const key =
      createPrivateKeyImpl(
        source
      );

    if (
      key?.type !== "private" ||
      key?.asymmetricKeyType !==
        "rsa" ||
      !Number.isSafeInteger(
        key.asymmetricKeyDetails
          ?.modulusLength
      ) ||
      key.asymmetricKeyDetails
        .modulusLength < 2048
    ) failure();

    return key;
  } catch {
    failure();
  } finally {
    try {
      await handle?.close();
    } catch {}
  }
};

const validateServiceToken = (
  value
) => {
  const result =
    exactRecord(
      value,
      [
        "access_token",
        "token_type",
        "expires_in",
        "scope"
      ]
    );

  if (
    !boundedBearer(
      result.access_token
    ) ||
    result.token_type !==
      "Bearer" ||
    result.expires_in !== 60 ||
    result.scope !==
      MESSAGING_RECIPIENT_SCOPE
  ) failure();

  return result.access_token;
};


const validateX25519PublicKey = (
  value
) => {
  if (
    typeof value !== "string" ||
    !HEX64.test(value) ||
    PROHIBITED_X25519.has(
      value
    )
  ) failure();

  const bytes =
    Buffer.from(
      value,
      "hex"
    );

  if (
    bytes.length !== 32 ||
    (bytes[31] & 0x80) !== 0
  ) failure();

  let integer = 0n;

  for (
    let index = 31;
    index >= 0;
    index -= 1
  ) {
    integer =
      (integer << 8n) |
      BigInt(bytes[index]);
  }

  if (
    integer >=
    X25519_FIELD_PRIME
  ) failure();

  return value;
};

const normalizeDevice = (
  value
) => {
  const record =
    exactRecord(
      value,
      [
        "deviceHandle",
        "algorithm",
        "version",
        "publicKey",
        "validFrom",
        "expiresAt"
      ]
    );

  if (
    typeof record.deviceHandle !==
      "string" ||
    !DEVICE_HANDLE.test(
      record.deviceHandle
    ) ||
    record.algorithm !==
      ALGORITHM ||
    !Number.isSafeInteger(
      record.version
    ) ||
    record.version < 1 ||
    record.version >
      MAX_BINDING_VERSION ||
    validateX25519PublicKey(
      record.publicKey
    ) !== record.publicKey ||
    !Number.isSafeInteger(
      record.validFrom
    ) ||
    !Number.isSafeInteger(
      record.expiresAt
    ) ||
    record.validFrom < 0 ||
    record.expiresAt <=
      record.validFrom
  ) failure();

  return Object.freeze({
    deviceHandle:
      record.deviceHandle,
    algorithm:
      record.algorithm,
    version: record.version,
    publicKey:
      record.publicKey,
    validFrom:
      record.validFrom,
    expiresAt:
      record.expiresAt
  });
};

export function normalizeMessagingRecipientPackage(
  value,
  {
    expectedAlias
  } = {}
) {
  if (
    typeof expectedAlias !==
      "string" ||
    !ALIAS.test(expectedAlias)
  ) failure();

  const record =
    exactRecord(
      value,
      [
        "schema",
        "version",
        "source",
        "snapshotId",
        "complete",
        "alias",
        "issuedAt",
        "expiresAt",
        "devices"
      ]
    );

  if (
    record.schema !==
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA ||
    record.version !== VERSION ||
    record.source !== SOURCE ||
    typeof record.snapshotId !==
      "string" ||
    !SNAPSHOT_ID.test(
      record.snapshotId
    ) ||
    record.complete !== true ||
    record.alias !==
      expectedAlias ||
    !Number.isSafeInteger(
      record.issuedAt
    ) ||
    !Number.isSafeInteger(
      record.expiresAt
    ) ||
    record.issuedAt < 0 ||
    record.expiresAt <=
      record.issuedAt ||
    !Array.isArray(
      record.devices
    ) ||
    Object.getPrototypeOf(
      record.devices
    ) !== Array.prototype ||
    record.devices.length < 1 ||
    record.devices.length >
      MAX_ACTIVE_DEVICES
  ) failure();

  const descriptors =
    Object.getOwnPropertyDescriptors(
      record.devices
    );

  if (
    Reflect.ownKeys(
      descriptors
    ).length !==
      record.devices.length + 1
  ) failure();

  const devices = [];
  const handles = new Set();
  const publicKeys = new Set();

  for (
    let index = 0;
    index <
      record.devices.length;
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
    ) failure();

    const device =
      normalizeDevice(
        descriptor.value
      );

    if (
      handles.has(
        device.deviceHandle
      ) ||
      publicKeys.has(
        device.publicKey
      ) ||
      device.validFrom >
        record.issuedAt ||
      device.expiresAt <
        record.expiresAt
    ) failure();

    handles.add(
      device.deviceHandle
    );
    publicKeys.add(
      device.publicKey
    );
    devices.push(device);
  }

  devices.sort(
    (left, right) =>
      left.deviceHandle.localeCompare(
        right.deviceHandle
      )
  );

  const canonicalDevices =
    devices.map(
      (device) => ({
        algorithm:
          device.algorithm,
        deviceHandle:
          device.deviceHandle,
        expiresAt:
          device.expiresAt,
        publicKey:
          device.publicKey,
        validFrom:
          device.validFrom,
        version:
          device.version
      })
    );

  const evidence = {
    alias: expectedAlias,
    complete: true,
    devices:
      canonicalDevices,
    expiresAt:
      record.expiresAt,
    issuedAt:
      record.issuedAt,
    schema:
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
    source: SOURCE,
    version: VERSION
  };

  const snapshotId =
    "sha256:" +
    createHash("sha256")
      .update(
        JSON.stringify(evidence),
        "ascii"
      )
      .digest("hex");

  if (
    record.snapshotId !==
      snapshotId
  ) failure();

  return Object.freeze({
    schema:
      MESSAGING_RECIPIENT_PACKAGE_SCHEMA,
    version: VERSION,
    source: SOURCE,
    snapshotId,
    complete: true,
    alias: expectedAlias,
    issuedAt:
      record.issuedAt,
    expiresAt:
      record.expiresAt,
    devices:
      Object.freeze(devices)
  });
}

export async function createUbidMessagingRecipientClient(
  config,
  {
    requestImpl = http.request,
    openFileImpl = openFile,
    createPrivateKeyImpl =
      createPrivateKey,
    now = Date.now,
    random = randomBytes,
    signImpl = sign
  } = {}
) {
  if (
    !validConfig(config) ||
    typeof requestImpl !==
      "function"
  ) failure();

  const tokenEndpoint =
    canonicalHttpsEndpoint(
      config.serviceTokenUrl,
      UBID_MESSAGING_RECIPIENT_SERVICE_TOKEN_PATH
    );

  const recipientEndpoint =
    canonicalHttpsEndpoint(
      config.recipientDevicesUrl,
      UBID_MESSAGING_RECIPIENT_DEVICES_PATH
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
        [
          "grant_type",
          GRANT_TYPE
        ],
        [
          "client_id",
          config.clientId
        ],
        [
          "scope",
          MESSAGING_RECIPIENT_SCOPE
        ],
        [
          "client_assertion_type",
          CLIENT_ASSERTION_TYPE
        ],
        [
          "client_assertion",
          assertion
        ]
      ]).toString();

    const value =
      await unixJsonRequest(
        {
          socketPath:
            config.socketPath,
          endpoint:
            tokenEndpoint,
          method: "POST",
          headers: {
            Accept:
              "application/json",
            "Content-Type":
              "application/x-www-form-urlencoded"
          },
          body,
          timeoutMs:
            config.tokenTimeoutMs,
          maximumBytes:
            TOKEN_MAX_BYTES
        },
        requestImpl
      );

    return validateServiceToken(
      value
    );
  };

  return Object.freeze({
    async resolveForViewer(
      {
        viewerAccessToken,
        recipientAlias
      } = {}
    ) {
      if (
        !boundedBearer(
          viewerAccessToken
        ) ||
        typeof recipientAlias !==
          "string" ||
        !ALIAS.test(
          recipientAlias
        )
      ) failure();

      const token =
        await serviceToken();

      if (
        token === viewerAccessToken
      ) failure();

      const body =
        JSON.stringify({
          recipientAlias
        });

      const value =
        await unixJsonRequest(
          {
            socketPath:
              config.socketPath,
            endpoint:
              recipientEndpoint,
            method: "POST",
            headers: {
              Accept:
                "application/json",
              Authorization:
                `Bearer ${token}`,
              "X-HODLXXI-Viewer-Authorization":
                `Bearer ${viewerAccessToken}`,
              "Content-Type":
                "application/json"
            },
            body,
            timeoutMs:
              config.requestTimeoutMs,
            maximumBytes:
              PACKAGE_MAX_BYTES
          },
          requestImpl
        );

      return normalizeMessagingRecipientPackage(
        value,
        {
          expectedAlias:
            recipientAlias
        }
      );
    }
  });
}
