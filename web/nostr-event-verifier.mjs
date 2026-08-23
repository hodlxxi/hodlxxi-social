const FIELD_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GENERATOR = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
});
const INFINITY = Object.freeze({ x: 0n, y: 1n, z: 0n });
const EVENT_FIELDS = Object.freeze([
  "content",
  "created_at",
  "id",
  "kind",
  "pubkey",
  "sig",
  "tags"
]);
const LOWER_HEX_32 = /^[0-9a-f]{64}$/;
const LOWER_HEX_64 = /^[0-9a-f]{128}$/;
const HEX = /^[0-9a-fA-F]*$/;
const MAX_EVENT_BYTES = 262_144;
const MAX_CONTENT_BYTES = 131_072;
const MAX_TAGS = 256;
const MAX_TAG_VALUES = 32;
const MAX_TAG_VALUE_BYTES = 16_384;
const BIP340_CHALLENGE = new TextEncoder().encode("BIP0340/challenge");

const invalidEvent = () => {
  throw new TypeError("invalid Nostr event");
};

const mod = (value, modulus = FIELD_P) => {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
};

const powMod = (base, exponent, modulus = FIELD_P) => {
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;

  while (power > 0n) {
    if (power & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }

  return result;
};

const isInfinity = (point) => point.z === 0n;
const toJacobian = ({ x, y }) => ({ x, y, z: 1n });

const doubleJacobian = (point) => {
  if (isInfinity(point) || point.y === 0n) return INFINITY;

  const xx = mod(point.x * point.x);
  const yy = mod(point.y * point.y);
  const yyyy = mod(yy * yy);
  const s = mod(2n * (mod((point.x + yy) * (point.x + yy)) - xx - yyyy));
  const m = mod(3n * xx);
  const x = mod(m * m - 2n * s);
  const y = mod(m * (s - x) - 8n * yyyy);
  const z = mod(2n * point.y * point.z);

  return { x, y, z };
};

const addJacobian = (left, right) => {
  if (isInfinity(left)) return right;
  if (isInfinity(right)) return left;

  const z1z1 = mod(left.z * left.z);
  const z2z2 = mod(right.z * right.z);
  const u1 = mod(left.x * z2z2);
  const u2 = mod(right.x * z1z1);
  const s1 = mod(left.y * right.z * z2z2);
  const s2 = mod(right.y * left.z * z1z1);

  if (u1 === u2) {
    return s1 === s2 ? doubleJacobian(left) : INFINITY;
  }

  const h = mod(u2 - u1);
  const i = mod(4n * h * h);
  const j = mod(h * i);
  const r = mod(2n * (s2 - s1));
  const v = mod(u1 * i);
  const x = mod(r * r - j - 2n * v);
  const y = mod(r * (v - x) - 2n * s1 * j);
  const z = mod((mod((left.z + right.z) * (left.z + right.z)) - z1z1 - z2z2) * h);

  return { x, y, z };
};

const multiplyPoint = (scalar, point) => {
  let result = INFINITY;
  let addend = toJacobian(point);
  let value = scalar;

  while (value > 0n) {
    if (value & 1n) result = addJacobian(result, addend);
    addend = doubleJacobian(addend);
    value >>= 1n;
  }

  return result;
};

const toAffine = (point) => {
  if (isInfinity(point)) return null;
  const inverse = powMod(point.z, FIELD_P - 2n);
  const inverseSquared = mod(inverse * inverse);
  return Object.freeze({
    x: mod(point.x * inverseSquared),
    y: mod(point.y * inverseSquared * inverse)
  });
};

const liftX = (x) => {
  if (x >= FIELD_P) return null;
  const curveY = mod(x * x * x + 7n);
  let y = powMod(curveY, (FIELD_P + 1n) >> 2n);
  if (mod(y * y) !== curveY) return null;
  if (y & 1n) y = FIELD_P - y;
  return Object.freeze({ x, y });
};

const bytesToBigInt = (bytes) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const bytesToHex = (bytes) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const hexToBytes = (value, exactBytes = null) => {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    !HEX.test(value) ||
    (exactBytes !== null && value.length !== exactBytes * 2)
  ) {
    throw new TypeError("invalid BIP340 input");
  }

  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
};

const sha256 = async (bytes, cryptoImpl) => {
  if (
    !cryptoImpl?.subtle ||
    typeof cryptoImpl.subtle.digest !== "function"
  ) {
    throw new TypeError("Nostr verification unavailable");
  }

  const result = await cryptoImpl.subtle.digest("SHA-256", bytes);
  return new Uint8Array(result);
};

const concatBytes = (...values) => {
  const length = values.reduce((total, value) => total + value.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
};

const copyStringArray = (value) => {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_TAG_VALUES) {
    invalidEvent();
  }

  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) =>
      typeof key !== "string" ||
      (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key))
    )
  ) {
    invalidEvent();
  }

  const copied = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      !descriptor ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string" ||
      new TextEncoder().encode(descriptor.value).byteLength > MAX_TAG_VALUE_BYTES
    ) {
      invalidEvent();
    }
    copied.push(descriptor.value);
  }

  if (keys.length !== copied.length + 1) invalidEvent();
  return Object.freeze(copied);
};

const normalizeWireEvent = (event) => {
  if (
    event === null ||
    typeof event !== "object" ||
    Array.isArray(event) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(event))
  ) {
    invalidEvent();
  }

  const keys = Reflect.ownKeys(event);
  const stringKeys = keys.filter((key) => typeof key === "string").sort();
  if (
    keys.length !== EVENT_FIELDS.length ||
    stringKeys.length !== EVENT_FIELDS.length ||
    EVENT_FIELDS.some((field, index) => stringKeys[index] !== field)
  ) {
    invalidEvent();
  }

  const values = Object.create(null);
  for (const field of EVENT_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(event, field);
    if (
      !descriptor?.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalidEvent();
    }
    values[field] = descriptor.value;
  }

  if (
    typeof values.id !== "string" ||
    !LOWER_HEX_32.test(values.id) ||
    typeof values.pubkey !== "string" ||
    !LOWER_HEX_32.test(values.pubkey) ||
    typeof values.sig !== "string" ||
    !LOWER_HEX_64.test(values.sig) ||
    !Number.isSafeInteger(values.created_at) ||
    values.created_at < 0 ||
    !Number.isSafeInteger(values.kind) ||
    values.kind < 0 ||
    values.kind > 65_535 ||
    typeof values.content !== "string" ||
    new TextEncoder().encode(values.content).byteLength > MAX_CONTENT_BYTES ||
    !Array.isArray(values.tags) ||
    values.tags.length > MAX_TAGS
  ) {
    invalidEvent();
  }

  const tagKeys = Reflect.ownKeys(values.tags);
  if (
    tagKeys.some((key) =>
      typeof key !== "string" ||
      (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key))
    ) ||
    tagKeys.length !== values.tags.length + 1
  ) {
    invalidEvent();
  }

  const tags = [];
  for (let index = 0; index < values.tags.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(values.tags, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, "value")) invalidEvent();
    tags.push(copyStringArray(descriptor.value));
  }

  return Object.freeze({
    id: values.id,
    pubkey: values.pubkey,
    created_at: values.created_at,
    kind: values.kind,
    tags: Object.freeze(tags),
    content: values.content,
    sig: values.sig
  });
};

const serializedEventBytes = (event) => {
  const bytes = new TextEncoder().encode(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]));

  if (bytes.byteLength > MAX_EVENT_BYTES) invalidEvent();
  return bytes;
};

export async function verifyBip340Signature(
  publicKeyHex,
  messageHex,
  signatureHex,
  { cryptoImpl = globalThis.crypto } = {}
) {
  const publicKeyBytes = hexToBytes(publicKeyHex, 32);
  const messageBytes = hexToBytes(messageHex);
  const signatureBytes = hexToBytes(signatureHex, 64);
  const publicKey = liftX(bytesToBigInt(publicKeyBytes));
  const r = bytesToBigInt(signatureBytes.slice(0, 32));
  const s = bytesToBigInt(signatureBytes.slice(32));

  if (!publicKey || r >= FIELD_P || s >= CURVE_N) return false;

  const tagHash = await sha256(BIP340_CHALLENGE, cryptoImpl);
  const challengeHash = await sha256(
    concatBytes(
      tagHash,
      tagHash,
      signatureBytes.slice(0, 32),
      publicKeyBytes,
      messageBytes
    ),
    cryptoImpl
  );
  const challenge = bytesToBigInt(challengeHash) % CURVE_N;
  const negativeChallenge = challenge === 0n ? 0n : CURVE_N - challenge;
  const candidate = addJacobian(
    multiplyPoint(s, GENERATOR),
    multiplyPoint(negativeChallenge, publicKey)
  );
  const point = toAffine(candidate);

  return Boolean(point && !(point.y & 1n) && point.x === r);
}

export async function computeNostrEventId(
  event,
  { cryptoImpl = globalThis.crypto } = {}
) {
  const normalized = normalizeWireEvent(event);
  return bytesToHex(await sha256(serializedEventBytes(normalized), cryptoImpl));
}

export async function verifyNostrEvent(
  event,
  { cryptoImpl = globalThis.crypto } = {}
) {
  const normalized = normalizeWireEvent(event);
  const computedId = bytesToHex(
    await sha256(serializedEventBytes(normalized), cryptoImpl)
  );

  if (
    computedId !== normalized.id ||
    !await verifyBip340Signature(
      normalized.pubkey,
      normalized.id,
      normalized.sig,
      { cryptoImpl }
    )
  ) {
    invalidEvent();
  }

  return normalized;
}
