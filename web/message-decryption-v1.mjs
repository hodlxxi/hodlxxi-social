// Local recipient only. This module does not read an inbox, grant access, or
// import a device private key from a server. The caller supplies its current
// non-extractable X25519 CryptoKey after authoritative binding reconciliation.
import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256
} from "./vendor/hpke-core-v1.9.0.mjs";
import {
  MAX_PLAINTEXT_BYTES,
  MESSAGE_ENVELOPE_SCHEMA,
  MESSAGE_ENVELOPE_SUITE,
  messageEnvelopeHeaderBytesV1,
  messageKeyWrapAadV1,
  messageKeyWrapInfoV1
} from "./message-encryption-v128e.mjs";

const unavailable = () => {
  throw new Error("message decryption unavailable");
};
const MESSAGE_ID = /^m_[A-Za-z0-9_-]{43}$/;
const DEVICE_HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const BODY_ALGORITHM = "aes-256-gcm";
const WRAP_ALGORITHM = "hpke-base-x25519-hkdfsha256-aes128gcm-v1";
const ENVELOPE_FIELDS = [
  "schema", "version", "suite", "messageId", "recipientPackageSnapshotId",
  "recipientDeviceHandles", "body", "keyWraps"
];
const BODY_FIELDS = ["algorithm", "nonce", "ciphertext"];
const WRAP_FIELDS = ["deviceHandle", "algorithm", "enc", "ciphertext"];

function exactRecord(input, fields) {
  if (input === null || typeof input !== "object" || Array.isArray(input) ||
      Object.getPrototypeOf(input) !== Object.prototype) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== fields.length || fields.some((field) =>
    !Object.hasOwn(descriptors, field) ||
    !descriptors[field].enumerable ||
    !Object.hasOwn(descriptors[field], "value")
  )) unavailable();
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
}

function exactArray(input, minimum, maximum) {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype ||
      input.length < minimum || input.length > maximum) unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== input.length + 1 ||
      !Object.hasOwn(descriptors, "length")) unavailable();
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value")) unavailable();
  }
  return Array.from({ length: input.length }, (_, index) =>
    descriptors[String(index)].value
  );
}

function decodeBase64url(input, minimum, maximum, atobImpl, btoaImpl) {
  if (typeof input !== "string" || !BASE64URL.test(input) ||
      input.length > 22_000) unavailable();
  const padded = input.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat((4 - (input.length % 4)) % 4);
  const binary = atobImpl(padded);
  if (binary.length < minimum || binary.length > maximum ||
      btoaImpl(binary).replaceAll("+", "-").replaceAll("/", "_")
        .replace(/=+$/u, "") !== input) unavailable();
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decodeEnvelope(input, atobImpl, btoaImpl) {
  const envelope = exactRecord(input, ENVELOPE_FIELDS);
  if (envelope.schema !== MESSAGE_ENVELOPE_SCHEMA || envelope.version !== 1 ||
      envelope.suite !== MESSAGE_ENVELOPE_SUITE ||
      typeof envelope.messageId !== "string" || !MESSAGE_ID.test(envelope.messageId) ||
      typeof envelope.recipientPackageSnapshotId !== "string" ||
      !SNAPSHOT_ID.test(envelope.recipientPackageSnapshotId)) unavailable();
  decodeBase64url(envelope.messageId.slice(2), 32, 32, atobImpl, btoaImpl);

  const handles = exactArray(envelope.recipientDeviceHandles, 1, 16);
  const wraps = exactArray(envelope.keyWraps, handles.length, handles.length);
  const validatedWraps = [];
  for (let index = 0; index < handles.length; index += 1) {
    const handle = handles[index];
    if (typeof handle !== "string" || !DEVICE_HANDLE.test(handle) ||
        (index > 0 && handles[index - 1] >= handle)) unavailable();
    decodeBase64url(handle.slice(2), 16, 16, atobImpl, btoaImpl);
    const wrap = exactRecord(wraps[index], WRAP_FIELDS);
    if (wrap.deviceHandle !== handle || wrap.algorithm !== WRAP_ALGORITHM) {
      unavailable();
    }
    validatedWraps.push({
      deviceHandle: handle,
      enc: decodeBase64url(wrap.enc, 32, 32, atobImpl, btoaImpl),
      ciphertext: decodeBase64url(wrap.ciphertext, 48, 48, atobImpl, btoaImpl)
    });
  }

  const body = exactRecord(envelope.body, BODY_FIELDS);
  if (body.algorithm !== BODY_ALGORITHM) unavailable();
  return {
    messageId: envelope.messageId,
    recipientPackageSnapshotId: envelope.recipientPackageSnapshotId,
    recipientDeviceHandles: handles,
    nonce: decodeBase64url(body.nonce, 12, 12, atobImpl, btoaImpl),
    ciphertext: decodeBase64url(body.ciphertext, 17, MAX_PLAINTEXT_BYTES + 16, atobImpl, btoaImpl),
    wraps: validatedWraps
  };
}

const suite = () => new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm()
});

async function decrypt(input, { cryptoImpl, atobImpl, btoaImpl, hpkeSuiteFactory }) {
  let messageKey;
  let plaintextBytes;
  try {
    const { envelope, deviceHandle, privateKey } = exactRecord(
      input, ["envelope", "deviceHandle", "privateKey"]
    );
    if (!cryptoImpl?.subtle || typeof cryptoImpl.subtle.importKey !== "function" ||
        typeof cryptoImpl.subtle.decrypt !== "function" ||
        typeof atobImpl !== "function" || typeof btoaImpl !== "function" ||
        typeof hpkeSuiteFactory !== "function" ||
        typeof deviceHandle !== "string" || !DEVICE_HANDLE.test(deviceHandle) ||
        privateKey?.type !== "private" || privateKey.extractable !== false ||
        privateKey.algorithm?.name !== "X25519" ||
        !Array.isArray(privateKey.usages) ||
        privateKey.usages.length !== 1 || privateKey.usages[0] !== "deriveBits") {
      unavailable();
    }
    const parsed = decodeEnvelope(envelope, atobImpl, btoaImpl);
    const wrap = parsed.wraps.find((item) => item.deviceHandle === deviceHandle);
    if (!wrap) unavailable();
    const header = messageEnvelopeHeaderBytesV1(parsed);
    messageKey = new Uint8Array(await hpkeSuiteFactory().open(
      {
        recipientKey: privateKey,
        enc: wrap.enc,
        info: messageKeyWrapInfoV1(parsed.messageId)
      },
      wrap.ciphertext,
      messageKeyWrapAadV1(header, deviceHandle)
    ));
    if (messageKey.length !== 32) unavailable();
    const bodyKey = await cryptoImpl.subtle.importKey(
      "raw", messageKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    plaintextBytes = new Uint8Array(await cryptoImpl.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: parsed.nonce,
        additionalData: header,
        tagLength: 128
      },
      bodyKey,
      parsed.ciphertext
    ));
    if (plaintextBytes.length < 1 || plaintextBytes.length > MAX_PLAINTEXT_BYTES) {
      unavailable();
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintextBytes);
  } catch {
    unavailable();
  } finally {
    messageKey?.fill(0);
    plaintextBytes?.fill(0);
  }
}

export const decryptMessageEnvelopeV1 = (input) => decrypt(input, {
  cryptoImpl: globalThis.crypto,
  atobImpl: globalThis.atob,
  btoaImpl: globalThis.btoa,
  hpkeSuiteFactory: suite
});
