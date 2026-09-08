// V1.28F.1 validates ciphertext envelopes in memory. It has no routing,
// transport, storage, database, filesystem, timer, or process-start behavior.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";

export const MESSAGE_ENVELOPE_SCHEMA =
  "hodlxxi.social_message_envelope.v1";
export const MESSAGE_ENVELOPE_VERSION = 1;
export const MESSAGE_ENVELOPE_SUITE =
  "hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1";
export const MESSAGE_BODY_ALGORITHM = "aes-256-gcm";
export const MESSAGE_KEY_WRAP_ALGORITHM =
  "hpke-base-x25519-hkdfsha256-aes128gcm-v1";
export const MESSAGE_ENVELOPE_DIGEST_DOMAIN =
  "HODLXXI_SOCIAL_MESSAGE_ENVELOPE_DIGEST_V1";
export const MAX_MESSAGE_ENVELOPE_WIRE_BYTES = 32_768;
export const MAX_MESSAGE_RECIPIENT_DEVICES = 16;

const FAILURE_MESSAGE = "message envelope unavailable";
const TOP_LEVEL_FIELDS = [
  "schema",
  "version",
  "suite",
  "messageId",
  "recipientPackageSnapshotId",
  "recipientDeviceHandles",
  "body",
  "keyWraps"
];
const BODY_FIELDS = ["algorithm", "nonce", "ciphertext"];
const WRAP_FIELDS = [
  "deviceHandle",
  "algorithm",
  "enc",
  "ciphertext"
];
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const DEVICE_HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SNAPSHOT_ID = /^sha256:[0-9a-f]{64}$/;

const failure = () => {
  throw new TypeError(FAILURE_MESSAGE);
};

function exactRecord(value, fields) {
  if (
    value === null ||
    typeof value !== "object" ||
    isProxy(value) ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) failure();

  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    fields.some((field) => !Object.hasOwn(descriptors, field)) ||
    keys.some((key) =>
      typeof key !== "string" ||
      !fields.includes(key) ||
      descriptors[key].enumerable !== true ||
      !Object.hasOwn(descriptors[key], "value")
    )
  ) failure();
  for (const key in value) {
    if (!Object.hasOwn(value, key)) failure();
  }

  return Object.fromEntries(
    fields.map((field) => [field, descriptors[field].value])
  );
}

function exactArray(value, minimum, maximum) {
  if (
    !Array.isArray(value) ||
    isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < minimum ||
    value.length > maximum
  ) failure();

  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const lengthDescriptor = descriptors.length;
  if (
    keys.length !== value.length + 1 ||
    !lengthDescriptor ||
    lengthDescriptor.enumerable !== false ||
    !Object.hasOwn(lengthDescriptor, "value") ||
    lengthDescriptor.value !== value.length ||
    keys.some((key) => {
      if (key === "length") return false;
      if (
        typeof key !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= value.length
      ) return true;
      const descriptor = descriptors[key];
      return descriptor.enumerable !== true ||
        !Object.hasOwn(descriptor, "value");
    })
  ) failure();
  for (const key in value) {
    if (!Object.hasOwn(value, key)) failure();
  }

  return Array.from(
    { length: value.length },
    (_, index) => descriptors[String(index)].value
  );
}

function canonicalBase64url(value, minimumBytes, maximumBytes) {
  if (
    typeof value !== "string" ||
    value.length < Math.ceil(minimumBytes * 4 / 3) ||
    value.length > Math.ceil(maximumBytes * 4 / 3) ||
    !BASE64URL.test(value) ||
    value.includes("=")
  ) failure();

  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes ||
    decoded.toString("base64url") !== value
  ) failure();

  return value;
}

function normalizeUnsafe(value) {
  const record = exactRecord(value, TOP_LEVEL_FIELDS);
  if (
    record.schema !== MESSAGE_ENVELOPE_SCHEMA ||
    record.version !== MESSAGE_ENVELOPE_VERSION ||
    record.suite !== MESSAGE_ENVELOPE_SUITE ||
    typeof record.messageId !== "string" ||
    !/^m_[A-Za-z0-9_-]{43}$/.test(record.messageId) ||
    typeof record.recipientPackageSnapshotId !== "string" ||
    !SNAPSHOT_ID.test(record.recipientPackageSnapshotId)
  ) failure();
  canonicalBase64url(record.messageId.slice(2), 32, 32);

  const handles = exactArray(
    record.recipientDeviceHandles,
    1,
    MAX_MESSAGE_RECIPIENT_DEVICES
  );
  let previousHandle = null;
  for (const handle of handles) {
    if (
      typeof handle !== "string" ||
      !DEVICE_HANDLE.test(handle) ||
      (previousHandle !== null && previousHandle >= handle)
    ) failure();
    previousHandle = handle;
  }

  const body = exactRecord(record.body, BODY_FIELDS);
  if (body.algorithm !== MESSAGE_BODY_ALGORITHM) failure();
  canonicalBase64url(body.nonce, 12, 12);
  canonicalBase64url(body.ciphertext, 17, 16_400);

  const inputWraps = exactArray(record.keyWraps, handles.length, handles.length);
  const wraps = inputWraps.map((value, index) => {
    const wrap = exactRecord(value, WRAP_FIELDS);
    if (
      wrap.deviceHandle !== handles[index] ||
      wrap.algorithm !== MESSAGE_KEY_WRAP_ALGORITHM
    ) failure();
    canonicalBase64url(wrap.enc, 32, 32);
    canonicalBase64url(wrap.ciphertext, 48, 48);
    return Object.freeze({
      deviceHandle: wrap.deviceHandle,
      algorithm: wrap.algorithm,
      enc: wrap.enc,
      ciphertext: wrap.ciphertext
    });
  });

  return Object.freeze({
    schema: record.schema,
    version: record.version,
    suite: record.suite,
    messageId: record.messageId,
    recipientPackageSnapshotId: record.recipientPackageSnapshotId,
    recipientDeviceHandles: Object.freeze([...handles]),
    body: Object.freeze({
      algorithm: body.algorithm,
      nonce: body.nonce,
      ciphertext: body.ciphertext
    }),
    keyWraps: Object.freeze(wraps)
  });
}

export function normalizeMessageEnvelopeV1(value) {
  try {
    return normalizeUnsafe(value);
  } catch {
    failure();
  }
}

function serializeNormalized(envelope) {
  const handles = `[${envelope.recipientDeviceHandles
    .map((handle) => JSON.stringify(handle))
    .join(",")}]`;
  const wraps = `[${envelope.keyWraps
    .map((wrap) =>
      `{"deviceHandle":${JSON.stringify(wrap.deviceHandle)}` +
      `,"algorithm":${JSON.stringify(wrap.algorithm)}` +
      `,"enc":${JSON.stringify(wrap.enc)}` +
      `,"ciphertext":${JSON.stringify(wrap.ciphertext)}}`
    )
    .join(",")}]`;

  return `{"schema":${JSON.stringify(envelope.schema)}` +
    `,"version":${envelope.version}` +
    `,"suite":${JSON.stringify(envelope.suite)}` +
    `,"messageId":${JSON.stringify(envelope.messageId)}` +
    `,"recipientPackageSnapshotId":${JSON.stringify(envelope.recipientPackageSnapshotId)}` +
    `,"recipientDeviceHandles":${handles}` +
    `,"body":{"algorithm":${JSON.stringify(envelope.body.algorithm)}` +
    `,"nonce":${JSON.stringify(envelope.body.nonce)}` +
    `,"ciphertext":${JSON.stringify(envelope.body.ciphertext)}}` +
    `,"keyWraps":${wraps}}`;
}

export function serializeCanonicalMessageEnvelopeV1(value) {
  try {
    return serializeNormalized(normalizeUnsafe(value));
  } catch {
    failure();
  }
}

function boundedAsciiWire(value) {
  if (typeof value === "string") {
    if (
      value.length > MAX_MESSAGE_ENVELOPE_WIRE_BYTES ||
      /[^\u0000-\u007f]/.test(value)
    ) failure();
    return value;
  }

  if (
    value === null ||
    typeof value !== "object" ||
    isProxy(value) ||
    !(
      Object.getPrototypeOf(value) === Uint8Array.prototype ||
      Buffer.isBuffer(value)
    )
  ) failure();

  const copy = Buffer.from(value);
  if (
    copy.byteLength > MAX_MESSAGE_ENVELOPE_WIRE_BYTES ||
    copy.some((byte) => byte > 0x7f)
  ) failure();
  return copy.toString("ascii");
}

export function parseCanonicalMessageEnvelopeWireV1(value) {
  try {
    const wire = boundedAsciiWire(value);
    const envelope = normalizeUnsafe(JSON.parse(wire));
    if (serializeNormalized(envelope) !== wire) failure();
    return envelope;
  } catch {
    failure();
  }
}

export function digestCanonicalMessageEnvelopeV1(value) {
  try {
    const wire = serializeNormalized(normalizeUnsafe(value));
    const hex = createHash("sha256")
      .update(MESSAGE_ENVELOPE_DIGEST_DOMAIN, "ascii")
      .update(Buffer.from([0]))
      .update(wire, "ascii")
      .digest("hex");
    return `hodlxxi-social-message-envelope-v1-sha256:${hex}`;
  } catch {
    failure();
  }
}
