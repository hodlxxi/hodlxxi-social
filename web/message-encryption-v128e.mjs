// Browser-only, in-memory V1.28E message encryption. No transport or storage.
import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256
} from "./vendor/hpke-core-v1.9.0.mjs";

export const MAX_PLAINTEXT_BYTES = 16384;
export const MESSAGE_ENVELOPE_SCHEMA =
  "hodlxxi.social_message_envelope.v1";
export const MESSAGE_ENVELOPE_SUITE =
  "hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1";

const RECIPIENT_PACKAGE_SCHEMA =
  "hodlxxi.social_messaging_recipient_package.v1";
const RECIPIENT_SOURCE = "hodlxxi-ubid";
const DEVICE_ALGORITHM = "x25519-v1";
const BODY_ALGORITHM = "aes-256-gcm";
const WRAP_ALGORITHM =
  "hpke-base-x25519-hkdfsha256-aes128gcm-v1";
const KEY_WRAP_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGE_KEY_WRAP_V1";
const MAX_ACTIVE_DEVICES = 16;
const MAX_BINDING_VERSION = 1024;
const ALIAS = /^p_[A-Za-z0-9_-]{22}$/;
const DEVICE_HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const X25519_FIELD_PRIME = (1n << 255n) - 19n;
const PROHIBITED_X25519 = new Set([
  "00".repeat(32),
  "01" + "00".repeat(31),
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900",
  "ec" + "ff".repeat(30) + "7f",
  "ed" + "ff".repeat(30) + "7f",
  "ee" + "ff".repeat(30) + "7f"
]);
const INPUT_FIELDS = ["recipientPackage", "plaintext"];
const PACKAGE_FIELDS = [
  "schema", "version", "source", "snapshotId", "complete", "alias",
  "issuedAt", "expiresAt", "devices"
];
const DEVICE_FIELDS = [
  "deviceHandle", "algorithm", "version", "publicKey", "validFrom",
  "expiresAt"
];
const textEncoder = new TextEncoder();

const unavailable = () => {
  throw new Error("message encryption unavailable");
};

const integer = (value) =>
  Number.isSafeInteger(value) && value >= 0;

function exactRecord(value, fields) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) unavailable();

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);

    if (
      keys.length !== fields.length ||
      keys.some((key) =>
        typeof key !== "string" ||
        !fields.includes(key) ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value")
      ) ||
      fields.some((field) => !keys.includes(field))
    ) unavailable();

    return Object.fromEntries(
      fields.map((field) => [field, descriptors[field].value])
    );
  } catch {
    unavailable();
  }
}

function exactArray(value, minimum, maximum) {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < minimum ||
    value.length > maximum
  ) unavailable();

  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== value.length + 1 ||
    keys.some((key) =>
      key !== "length" &&
      (
        typeof key !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= value.length ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value")
      )
    )
  ) unavailable();

  return Array.from(
    { length: value.length },
    (_, index) => descriptors[String(index)].value
  );
}

function hexBytes(value) {
  if (typeof value !== "string" || !HEX64.test(value)) unavailable();
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function validX25519PublicKey(value) {
  if (PROHIBITED_X25519.has(value)) unavailable();
  const bytes = hexBytes(value);
  if ((bytes[31] & 0x80) !== 0) unavailable();

  let coordinate = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    coordinate = (coordinate << 8n) | BigInt(bytes[index]);
  }
  if (coordinate >= X25519_FIELD_PRIME) unavailable();
  return bytes;
}

function normalizeDevice(value, packageRecord, now) {
  const record = exactRecord(value, DEVICE_FIELDS);
  if (
    typeof record.deviceHandle !== "string" ||
    !DEVICE_HANDLE.test(record.deviceHandle) ||
    record.algorithm !== DEVICE_ALGORITHM ||
    !Number.isSafeInteger(record.version) ||
    record.version < 1 ||
    record.version > MAX_BINDING_VERSION ||
    !integer(record.validFrom) ||
    !integer(record.expiresAt) ||
    record.expiresAt <= record.validFrom ||
    record.validFrom > packageRecord.issuedAt ||
    record.expiresAt < packageRecord.expiresAt ||
    record.expiresAt <= now
  ) unavailable();

  const publicKeyBytes = validX25519PublicKey(record.publicKey);
  return Object.freeze({
    deviceHandle: record.deviceHandle,
    algorithm: record.algorithm,
    version: record.version,
    publicKey: record.publicKey,
    publicKeyBytes,
    validFrom: record.validFrom,
    expiresAt: record.expiresAt
  });
}

const lowerHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

async function normalizeRecipientPackage(value, now, cryptoImpl) {
  const record = exactRecord(value, PACKAGE_FIELDS);
  if (
    record.schema !== RECIPIENT_PACKAGE_SCHEMA ||
    record.version !== 1 ||
    record.source !== RECIPIENT_SOURCE ||
    typeof record.snapshotId !== "string" ||
    !SNAPSHOT_ID.test(record.snapshotId) ||
    record.complete !== true ||
    typeof record.alias !== "string" ||
    !ALIAS.test(record.alias) ||
    !integer(record.issuedAt) ||
    !integer(record.expiresAt) ||
    record.issuedAt > now ||
    record.expiresAt <= now ||
    record.expiresAt <= record.issuedAt
  ) unavailable();

  const inputDevices = exactArray(record.devices, 1, MAX_ACTIVE_DEVICES);
  const devices = inputDevices.map((device) =>
    normalizeDevice(device, record, now)
  );
  const handles = new Set();
  const publicKeys = new Set();
  let previousHandle = null;

  for (const device of devices) {
    if (
      handles.has(device.deviceHandle) ||
      publicKeys.has(device.publicKey) ||
      (previousHandle !== null && previousHandle >= device.deviceHandle)
    ) unavailable();
    handles.add(device.deviceHandle);
    publicKeys.add(device.publicKey);
    previousHandle = device.deviceHandle;
  }

  const evidence = {
    alias: record.alias,
    complete: true,
    devices: devices.map((device) => ({
      algorithm: device.algorithm,
      deviceHandle: device.deviceHandle,
      expiresAt: device.expiresAt,
      publicKey: device.publicKey,
      validFrom: device.validFrom,
      version: device.version
    })),
    expiresAt: record.expiresAt,
    issuedAt: record.issuedAt,
    schema: RECIPIENT_PACKAGE_SCHEMA,
    source: RECIPIENT_SOURCE,
    version: 1
  };
  const digest = await cryptoImpl.subtle.digest(
    "SHA-256",
    textEncoder.encode(JSON.stringify(evidence))
  );
  if (`sha256:${lowerHex(new Uint8Array(digest))}` !== record.snapshotId) {
    unavailable();
  }

  return Object.freeze({
    snapshotId: record.snapshotId,
    devices: Object.freeze(devices)
  });
}

function canonicalHeader({
  messageId,
  recipientPackageSnapshotId,
  recipientDeviceHandles
}) {
  return textEncoder.encode(
    `{"schema":${JSON.stringify(MESSAGE_ENVELOPE_SCHEMA)}` +
    `,"version":1` +
    `,"suite":${JSON.stringify(MESSAGE_ENVELOPE_SUITE)}` +
    `,"messageId":${JSON.stringify(messageId)}` +
    `,"recipientPackageSnapshotId":${JSON.stringify(recipientPackageSnapshotId)}` +
    `,"recipientDeviceHandles":${JSON.stringify(recipientDeviceHandles)}` +
    `,"bodyAlgorithm":${JSON.stringify(BODY_ALGORITHM)}}`
  );
}

function concatenate(left, separator, right) {
  const result = new Uint8Array(left.byteLength + 1 + right.byteLength);
  result.set(left, 0);
  result[left.byteLength] = separator;
  result.set(right, left.byteLength + 1);
  return result;
}

const wrapInfo = (messageId) => textEncoder.encode(
  `${KEY_WRAP_DOMAIN}\u0000${messageId}`
);

const wrapAad = (header, deviceHandle) =>
  concatenate(header, 0, textEncoder.encode(deviceHandle));

function base64url(bytes, btoaImpl) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 4096) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 4096));
  }
  const encoded = btoaImpl(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
  if (!BASE64URL.test(encoded) || encoded.includes("=")) unavailable();
  return encoded;
}

function randomBytes(length, randomFill) {
  const bytes = new Uint8Array(length);
  if (randomFill(bytes) !== bytes) unavailable();
  return bytes;
}

const defaultSuiteFactory = () => new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm()
});

function createEncryptor({
  cryptoImpl,
  randomFill,
  now,
  btoaImpl,
  hpkeSuiteFactory
}) {
  return async (input) => {
    let messageKey;
    let plaintextBytes;
    try {
      const request = exactRecord(input, INPUT_FIELDS);
      if (
        !cryptoImpl?.subtle ||
        typeof cryptoImpl.subtle.digest !== "function" ||
        typeof cryptoImpl.subtle.importKey !== "function" ||
        typeof cryptoImpl.subtle.encrypt !== "function" ||
        typeof randomFill !== "function" ||
        typeof now !== "function" ||
        typeof btoaImpl !== "function" ||
        typeof hpkeSuiteFactory !== "function" ||
        typeof request.plaintext !== "string"
      ) unavailable();

      const currentTime = now();
      if (!integer(currentTime)) unavailable();
      plaintextBytes = textEncoder.encode(request.plaintext);
      if (
        plaintextBytes.byteLength < 1 ||
        plaintextBytes.byteLength > MAX_PLAINTEXT_BYTES
      ) unavailable();

      const recipientPackage = await normalizeRecipientPackage(
        request.recipientPackage,
        currentTime,
        cryptoImpl
      );
      const messageIdBytes = randomBytes(32, randomFill);
      messageKey = randomBytes(32, randomFill);
      const bodyNonce = randomBytes(12, randomFill);
      const messageId = `m_${base64url(messageIdBytes, btoaImpl)}`;
      if (!/^m_[A-Za-z0-9_-]{43}$/.test(messageId)) unavailable();

      const recipientDeviceHandles = recipientPackage.devices.map(
        (device) => device.deviceHandle
      );
      const header = canonicalHeader({
        messageId,
        recipientPackageSnapshotId: recipientPackage.snapshotId,
        recipientDeviceHandles
      });
      const bodyKey = await cryptoImpl.subtle.importKey(
        "raw",
        messageKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const encryptedBody = new Uint8Array(
        await cryptoImpl.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: bodyNonce,
            additionalData: header,
            tagLength: 128
          },
          bodyKey,
          plaintextBytes
        )
      );
      if (encryptedBody.byteLength !== plaintextBytes.byteLength + 16) {
        unavailable();
      }

      const info = wrapInfo(messageId);
      const keyWraps = [];
      for (const device of recipientPackage.devices) {
        // A fresh suite plus its single-shot seal creates one independent Base
        // mode sender context for exactly one device and one content key.
        const suite = hpkeSuiteFactory();
        if (typeof suite?.seal !== "function") unavailable();
        if (typeof suite.kem?.deserializePublicKey !== "function") unavailable();
        const recipientPublicKey = await suite.kem.deserializePublicKey(
          device.publicKeyBytes
        );
        const wrapped = await suite.seal(
          {
            recipientPublicKey,
            info
          },
          messageKey,
          wrapAad(header, device.deviceHandle)
        );
        const enc = new Uint8Array(wrapped?.enc);
        const ciphertext = new Uint8Array(wrapped?.ct);
        if (enc.byteLength !== 32 || ciphertext.byteLength !== 48) unavailable();
        keyWraps.push(Object.freeze({
          deviceHandle: device.deviceHandle,
          algorithm: WRAP_ALGORITHM,
          enc: base64url(enc, btoaImpl),
          ciphertext: base64url(ciphertext, btoaImpl)
        }));
      }

      return Object.freeze({
        schema: MESSAGE_ENVELOPE_SCHEMA,
        version: 1,
        suite: MESSAGE_ENVELOPE_SUITE,
        messageId,
        recipientPackageSnapshotId: recipientPackage.snapshotId,
        recipientDeviceHandles: Object.freeze([...recipientDeviceHandles]),
        body: Object.freeze({
          algorithm: BODY_ALGORITHM,
          nonce: base64url(bodyNonce, btoaImpl),
          ciphertext: base64url(encryptedBody, btoaImpl)
        }),
        keyWraps: Object.freeze(keyWraps)
      });
    } catch {
      unavailable();
    } finally {
      messageKey?.fill(0);
      plaintextBytes?.fill(0);
    }
  };
}

export const encryptMessageEnvelope = (input) => createEncryptor({
  cryptoImpl: globalThis.crypto,
  randomFill: (bytes) => globalThis.crypto.getRandomValues(bytes),
  now: Date.now,
  btoaImpl: globalThis.btoa,
  hpkeSuiteFactory: defaultSuiteFactory
})(input);

// Explicit test seam. Production callers use encryptMessageEnvelope and cannot
// supply clocks, randomness, keys, nonces, identifiers, or HPKE contexts.
export function createMessageEnvelopeEncryptorForTest({
  cryptoImpl = globalThis.crypto,
  randomFill = (bytes) => cryptoImpl.getRandomValues(bytes),
  now = Date.now,
  btoaImpl = globalThis.btoa,
  hpkeSuiteFactory = defaultSuiteFactory
} = {}) {
  return createEncryptor({
    cryptoImpl,
    randomFill,
    now,
    btoaImpl,
    hpkeSuiteFactory
  });
}
