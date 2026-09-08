import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  digestCanonicalMessageEnvelopeV1,
  MAX_MESSAGE_ENVELOPE_WIRE_BYTES,
  MESSAGE_BODY_ALGORITHM,
  MESSAGE_ENVELOPE_DIGEST_DOMAIN,
  MESSAGE_ENVELOPE_SCHEMA,
  MESSAGE_ENVELOPE_SUITE,
  MESSAGE_KEY_WRAP_ALGORITHM,
  normalizeMessageEnvelopeV1,
  parseCanonicalMessageEnvelopeWireV1,
  serializeCanonicalMessageEnvelopeV1
} from "../src/server/message-envelope-v128f1.mjs";
import {
  encryptMessageEnvelope,
  MESSAGE_ENVELOPE_SCHEMA as V128E_MESSAGE_ENVELOPE_SCHEMA,
  MESSAGE_ENVELOPE_SUITE as V128E_MESSAGE_ENVELOPE_SUITE
} from "../web/message-encryption-v128e.mjs";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: webcrypto
  });
}

const syntheticBytes = (length, seed) => Buffer.from(
  { length },
  (_, index) => (seed + index * 29) % 256
);
const encoded = (length, seed) => syntheticBytes(length, seed)
  .toString("base64url");
const syntheticHandles = (count) => Array.from(
  { length: count },
  (_, index) => {
    const bytes = Buffer.alloc(16, 0xa5);
    bytes.writeUInt16BE(index, 0);
    return `d_${bytes.toString("base64url")}`;
  }
).sort();

const fixture = (count = 1) => {
  const recipientDeviceHandles = syntheticHandles(count);
  return {
    schema: MESSAGE_ENVELOPE_SCHEMA,
    version: 1,
    suite: MESSAGE_ENVELOPE_SUITE,
    messageId: `m_${encoded(32, 7)}`,
    recipientPackageSnapshotId: `sha256:${"2a".repeat(32)}`,
    recipientDeviceHandles,
    body: {
      algorithm: MESSAGE_BODY_ALGORITHM,
      nonce: encoded(12, 31),
      ciphertext: encoded(97, 53)
    },
    keyWraps: recipientDeviceHandles.map((deviceHandle, index) => ({
      deviceHandle,
      algorithm: MESSAGE_KEY_WRAP_ALGORITHM,
      enc: encoded(32, 71 + index),
      ciphertext: encoded(48, 109 + index)
    }))
  };
};

const clone = (value = fixture()) => structuredClone(value);
const errorContract = (operation) => assert.throws(
  operation,
  (error) => {
    assert.equal(error.constructor, TypeError);
    assert.equal(error.message, "message envelope unavailable");
    return true;
  }
);
const assertDeepFrozen = (value) => {
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") assertDeepFrozen(child);
  }
};
const replaceLast = (value, replacement) =>
  `${value.slice(0, -1)}${replacement}`;

test("normalizes the exact synthetic one-device ciphertext envelope", () => {
  const input = fixture();
  const normalized = normalizeMessageEnvelopeV1(input);
  assert.deepEqual(normalized, input);
  assert.notEqual(normalized, input);
  assert.notEqual(normalized.body, input.body);
  assert.notEqual(normalized.keyWraps[0], input.keyWraps[0]);
});

test("normalizes the exact 16-device maximum", () => {
  const input = fixture(16);
  const normalized = normalizeMessageEnvelopeV1(input);
  assert.equal(normalized.recipientDeviceHandles.length, 16);
  assert.equal(normalized.keyWraps.length, 16);
});

test("canonical serialization is stable and byte-identical to V1.28E field order", () => {
  const input = fixture(2);
  const first = serializeCanonicalMessageEnvelopeV1(input);
  const second = serializeCanonicalMessageEnvelopeV1(clone(input));
  assert.equal(MESSAGE_ENVELOPE_SCHEMA, V128E_MESSAGE_ENVELOPE_SCHEMA);
  assert.equal(MESSAGE_ENVELOPE_SUITE, V128E_MESSAGE_ENVELOPE_SUITE);
  assert.equal(first, second);
  assert.equal(first, JSON.stringify(input));
  assert.doesNotMatch(first, /\s/);
  assert.equal(Buffer.byteLength(first, "ascii"), first.length);
});

test("actual V1.28E output is byte-identical to the V1.28F.1 canonical wire", async () => {
  const observedAt = Date.now();
  const recipientAlias = `p_${"A".repeat(22)}`;
  const deviceHandle = `d_${"A".repeat(22)}`;
  const syntheticPlaintext = "synthetic-only input";
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveBits"]
  );
  assert.equal(keyPair.privateKey.extractable, false);
  assert.equal(keyPair.publicKey.extractable, true);

  const publicKey = Buffer.from(
    await webcrypto.subtle.exportKey("raw", keyPair.publicKey)
  ).toString("hex");
  const recipientPackage = {
    schema: "hodlxxi.social_messaging_recipient_package.v1",
    version: 1,
    source: "hodlxxi-ubid",
    snapshotId: "",
    complete: true,
    alias: recipientAlias,
    issuedAt: observedAt - 1_000,
    expiresAt: observedAt + 60_000,
    devices: [
      {
        deviceHandle,
        algorithm: "x25519-v1",
        version: 1,
        publicKey,
        validFrom: observedAt - 2_000,
        expiresAt: observedAt + 120_000
      }
    ]
  };
  const snapshotEvidence = {
    alias: recipientPackage.alias,
    complete: true,
    devices: recipientPackage.devices.map((device) => ({
      algorithm: device.algorithm,
      deviceHandle: device.deviceHandle,
      expiresAt: device.expiresAt,
      publicKey: device.publicKey,
      validFrom: device.validFrom,
      version: device.version
    })),
    expiresAt: recipientPackage.expiresAt,
    issuedAt: recipientPackage.issuedAt,
    schema: recipientPackage.schema,
    source: recipientPackage.source,
    version: recipientPackage.version
  };
  recipientPackage.snapshotId = `sha256:${createHash("sha256")
    .update(JSON.stringify(snapshotEvidence), "ascii")
    .digest("hex")}`;

  const actualEnvelope = await encryptMessageEnvelope({
    recipientPackage,
    plaintext: syntheticPlaintext
  });
  const actualWire = JSON.stringify(actualEnvelope);
  const parsed = parseCanonicalMessageEnvelopeWireV1(actualWire);
  const normalized = normalizeMessageEnvelopeV1(actualEnvelope);
  const canonical = serializeCanonicalMessageEnvelopeV1(actualEnvelope);
  const digest = digestCanonicalMessageEnvelopeV1(actualEnvelope);

  assert.equal(canonical, actualWire);
  assert.equal(serializeCanonicalMessageEnvelopeV1(parsed), actualWire);
  assert.deepEqual(parsed, actualEnvelope);
  assert.deepEqual(normalized, actualEnvelope);
  assertDeepFrozen(parsed);
  assertDeepFrozen(normalized);
  assert.match(
    digest,
    /^hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}$/
  );

  const f1Outputs = [actualWire, JSON.stringify(normalized), digest].join("\n");
  for (const forbiddenValue of [
    recipientAlias,
    publicKey,
    syntheticPlaintext
  ]) {
    assert.equal(f1Outputs.includes(forbiddenValue), false);
  }
  assert.doesNotMatch(
    f1Outputs,
    /"(?:alias|publicKey|plaintext|K_message|privateKey)"\s*:/
  );
});

test("canonical raw wire round trips from string, Buffer, and Uint8Array", () => {
  const canonical = serializeCanonicalMessageEnvelopeV1(fixture(2));
  for (const input of [
    canonical,
    Buffer.from(canonical, "ascii"),
    Uint8Array.from(Buffer.from(canonical, "ascii"))
  ]) {
    const parsed = parseCanonicalMessageEnvelopeWireV1(input);
    assert.equal(serializeCanonicalMessageEnvelopeV1(parsed), canonical);
    assertDeepFrozen(parsed);
  }
});

test("digest is stable, versioned, and domain separated", () => {
  const input = fixture(2);
  const wire = serializeCanonicalMessageEnvelopeV1(input);
  const digest = digestCanonicalMessageEnvelopeV1(input);
  assert.equal(
    digest,
    "hodlxxi-social-message-envelope-v1-sha256:" +
      "f669e5ba81422674fb22fd80284086599f6788c58ec38e49863c67bc53c8357a"
  );
  assert.equal(
    digest,
    "hodlxxi-social-message-envelope-v1-sha256:" +
      createHash("sha256")
        .update(MESSAGE_ENVELOPE_DIGEST_DOMAIN, "ascii")
        .update(Buffer.from([0]))
        .update(wire, "ascii")
        .digest("hex")
  );
  assert.equal(digest, digestCanonicalMessageEnvelopeV1(clone(input)));
  assert.match(
    digest,
    /^hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}$/
  );
  assert.notEqual(
    digest.slice(digest.lastIndexOf(":") + 1),
    createHash("sha256").update(wire, "ascii").digest("hex")
  );
  assert.notEqual(
    digest.slice(digest.lastIndexOf(":") + 1),
    createHash("sha256")
      .update("HODLXXI_SOCIAL_MESSAGE_ENVELOPE_DIGEST_V2\0", "ascii")
      .update(wire, "ascii")
      .digest("hex")
  );
});

test("normalized envelope is deeply frozen", () => {
  assertDeepFrozen(normalizeMessageEnvelopeV1(fixture(3)));
});

test("outputs contain only the frozen ciphertext-envelope vocabulary", () => {
  const normalized = normalizeMessageEnvelopeV1(fixture(2));
  assert.deepEqual(Object.keys(normalized), [
    "schema",
    "version",
    "suite",
    "messageId",
    "recipientPackageSnapshotId",
    "recipientDeviceHandles",
    "body",
    "keyWraps"
  ]);
  assert.deepEqual(Object.keys(normalized.body), [
    "algorithm",
    "nonce",
    "ciphertext"
  ]);
  assert.deepEqual(Object.keys(normalized.keyWraps[0]), [
    "deviceHandle",
    "algorithm",
    "enc",
    "ciphertext"
  ]);
  const outputs = [
    JSON.stringify(normalized),
    serializeCanonicalMessageEnvelopeV1(normalized),
    digestCanonicalMessageEnvelopeV1(normalized)
  ].join("\n");
  assert.doesNotMatch(
    outputs,
    /(?:preview|k_message|private.?key|canonical.?subject|public.?key|alias|capability|deviceid|bindingid|oauth|session|service.?token|private.?label|bitcoin|xpub|nostr|sponsor|covenant|friendship)/i
  );
});

test("rejects every missing and extra record field", () => {
  const cases = [
    [fixture(), [
      "schema", "version", "suite", "messageId",
      "recipientPackageSnapshotId", "recipientDeviceHandles", "body",
      "keyWraps"
    ]],
    [fixture().body, ["algorithm", "nonce", "ciphertext"]],
    [fixture().keyWraps[0], [
      "deviceHandle", "algorithm", "enc", "ciphertext"
    ]]
  ];
  for (const [sample, fields] of cases) {
    for (const field of fields) {
      const input = fixture();
      const target = sample === cases[0][0]
        ? input
        : fields.length === 3
          ? input.body
          : input.keyWraps[0];
      delete target[field];
      errorContract(() => normalizeMessageEnvelopeV1(input));
    }
    const input = fixture();
    const target = sample === cases[0][0]
      ? input
      : fields.length === 3
        ? input.body
        : input.keyWraps[0];
    target.unexpected = "synthetic-rejection-marker";
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects inherited fields and null or custom record prototypes", () => {
  const inherited = Object.create({ schema: MESSAGE_ENVELOPE_SCHEMA });
  Object.assign(inherited, fixture());
  delete inherited.schema;
  errorContract(() => normalizeMessageEnvelopeV1(inherited));

  Object.defineProperty(Object.prototype, "syntheticInheritedMarker", {
    configurable: true,
    enumerable: true,
    value: true
  });
  try {
    errorContract(() => normalizeMessageEnvelopeV1(fixture()));
  } finally {
    delete Object.prototype.syntheticInheritedMarker;
  }

  for (const mutate of [
    (input) => Object.setPrototypeOf(input, null),
    (input) => Object.setPrototypeOf(input, { inherited: true }),
    (input) => Object.setPrototypeOf(input.body, null),
    (input) => Object.setPrototypeOf(input.keyWraps[0], { inherited: true })
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects accessors and symbols at every envelope shape", () => {
  for (const select of [
    (input) => [input, "schema"],
    (input) => [input.body, "nonce"],
    (input) => [input.keyWraps[0], "enc"],
    (input) => [input.recipientDeviceHandles, "0"],
    (input) => [input.keyWraps, "0"]
  ]) {
    const input = fixture();
    const [target, field] = select(input);
    Object.defineProperty(target, field, {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error("synthetic-accessor-marker");
      }
    });
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }

  for (const select of [
    (input) => input,
    (input) => input.body,
    (input) => input.keyWraps[0],
    (input) => input.recipientDeviceHandles,
    (input) => input.keyWraps
  ]) {
    const input = fixture();
    select(input)[Symbol("synthetic-symbol-marker")] = true;
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects proxies and thrown proxy traps without reflecting trap details", () => {
  const trap = new Proxy(fixture(), {
    getOwnPropertyDescriptor() {
      throw new Error("synthetic-proxy-trap-marker");
    },
    ownKeys() {
      throw new Error("synthetic-proxy-trap-marker");
    }
  });
  errorContract(() => normalizeMessageEnvelopeV1(trap));

  const nested = fixture();
  nested.body = new Proxy(nested.body, {
    getPrototypeOf() {
      throw new Error("synthetic-nested-trap-marker");
    }
  });
  errorContract(() => normalizeMessageEnvelopeV1(nested));
});

test("rejects sparse, extended, and custom-prototype arrays", () => {
  for (const mutate of [
    (input) => { input.recipientDeviceHandles = new Array(1); },
    (input) => { input.keyWraps = new Array(1); },
    (input) => { input.recipientDeviceHandles.extra = true; },
    (input) => {
      Object.defineProperty(input.keyWraps, "extra", { value: true });
    },
    (input) => Object.setPrototypeOf(input.recipientDeviceHandles, null),
    (input) => Object.setPrototypeOf(input.keyWraps, {})
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects zero or 17 handles and unsorted or duplicate handles", () => {
  for (const input of [fixture(0), fixture(17)]) {
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }

  const unsorted = fixture(2);
  unsorted.recipientDeviceHandles.reverse();
  unsorted.keyWraps.reverse();
  errorContract(() => normalizeMessageEnvelopeV1(unsorted));

  const duplicate = fixture(2);
  duplicate.recipientDeviceHandles[1] = duplicate.recipientDeviceHandles[0];
  duplicate.keyWraps[1].deviceHandle = duplicate.recipientDeviceHandles[0];
  errorContract(() => normalizeMessageEnvelopeV1(duplicate));
});

test("rejects wrap count, order, and handle mismatches", () => {
  const omitted = fixture(2);
  omitted.keyWraps.pop();
  errorContract(() => normalizeMessageEnvelopeV1(omitted));

  const added = fixture(1);
  added.keyWraps.push(clone(added.keyWraps[0]));
  errorContract(() => normalizeMessageEnvelopeV1(added));

  const wrongOrder = fixture(2);
  wrongOrder.keyWraps.reverse();
  errorContract(() => normalizeMessageEnvelopeV1(wrongOrder));

  const wrongHandle = fixture();
  wrongHandle.keyWraps[0].deviceHandle = syntheticHandles(2)[1];
  errorContract(() => normalizeMessageEnvelopeV1(wrongHandle));
});

test("rejects wrong schema, version, suite, and algorithms", () => {
  for (const mutate of [
    (input) => { input.schema = "hodlxxi.social_message_envelope.v2"; },
    (input) => { input.version = 2; },
    (input) => { input.suite = `${MESSAGE_ENVELOPE_SUITE}-other`; },
    (input) => { input.body.algorithm = "aes-128-gcm"; },
    (input) => { input.keyWraps[0].algorithm = "unsupported-wrap-v1"; }
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects malformed message and snapshot identifiers", () => {
  for (const mutate of [
    (input) => { input.messageId = encoded(32, 7); },
    (input) => { input.messageId = `m_${encoded(31, 7)}`; },
    (input) => { input.messageId = `m_${encoded(32, 7)}x`; },
    (input) => { input.messageId = `m_${"!".repeat(43)}`; },
    (input) => { input.recipientPackageSnapshotId = "2a".repeat(32); },
    (input) => {
      input.recipientPackageSnapshotId = `sha256:${"2A".repeat(32)}`;
    },
    (input) => {
      input.recipientPackageSnapshotId = `sha256:${"2a".repeat(31)}`;
    }
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects invalid, padded, and noncanonical base64url", () => {
  for (const mutate of [
    (input) => {
      input.recipientDeviceHandles[0] = `d_${"A".repeat(21)}B`;
      input.keyWraps[0].deviceHandle = input.recipientDeviceHandles[0];
    },
    (input) => { input.body.nonce = `${input.body.nonce}=`; },
    (input) => { input.body.ciphertext = "invalid+alphabet"; },
    (input) => { input.keyWraps[0].enc = "invalid/alphabet"; },
    (input) => { input.keyWraps[0].ciphertext += "="; },
    (input) => {
      input.messageId = `m_${replaceLast(encoded(32, 0), "B")}`;
    },
    (input) => {
      input.body.ciphertext = replaceLast(encoded(17, 0), "B");
    },
    (input) => {
      input.keyWraps[0].enc = replaceLast(encoded(32, 0), "B");
    }
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("rejects every decoded-size mismatch and empty body ciphertext", () => {
  for (const mutate of [
    (input) => { input.messageId = `m_${encoded(31, 3)}`; },
    (input) => { input.body.nonce = encoded(11, 3); },
    (input) => { input.body.nonce = encoded(13, 3); },
    (input) => { input.body.ciphertext = encoded(16, 3); },
    (input) => { input.body.ciphertext = encoded(16_401, 3); },
    (input) => { input.body.ciphertext = ""; },
    (input) => { input.body.ciphertext = "A"; },
    (input) => { input.keyWraps[0].enc = encoded(31, 3); },
    (input) => { input.keyWraps[0].enc = encoded(33, 3); },
    (input) => { input.keyWraps[0].ciphertext = encoded(47, 3); },
    (input) => { input.keyWraps[0].ciphertext = encoded(49, 3); }
  ]) {
    const input = fixture();
    mutate(input);
    errorContract(() => normalizeMessageEnvelopeV1(input));
  }
});

test("raw wire rejects oversize, non-ASCII, and unsupported input shapes", () => {
  assert.equal(MAX_MESSAGE_ENVELOPE_WIRE_BYTES, 32_768);
  for (const input of [
    "x".repeat(MAX_MESSAGE_ENVELOPE_WIRE_BYTES + 1),
    Buffer.alloc(MAX_MESSAGE_ENVELOPE_WIRE_BYTES + 1, 0x41),
    "\u0080",
    Buffer.from([0x80]),
    new Uint16Array([0x41]),
    new Proxy(Buffer.from("{}", "ascii"), {})
  ]) {
    errorContract(() => parseCanonicalMessageEnvelopeWireV1(input));
  }
});

test("raw wire rejects whitespace, field reorder, alternate escapes, and duplicates", () => {
  const canonical = serializeCanonicalMessageEnvelopeV1(fixture());
  const parsed = JSON.parse(canonical);
  const reordered = JSON.stringify({
    version: parsed.version,
    schema: parsed.schema,
    suite: parsed.suite,
    messageId: parsed.messageId,
    recipientPackageSnapshotId: parsed.recipientPackageSnapshotId,
    recipientDeviceHandles: parsed.recipientDeviceHandles,
    body: parsed.body,
    keyWraps: parsed.keyWraps
  });
  const alternateEscape = canonical.replace(
    "hodlxxi.social_message_envelope.v1",
    "\\u0068odlxxi.social_message_envelope.v1"
  );
  const duplicate = canonical.replace(
    "{",
    `{"schema":${JSON.stringify(MESSAGE_ENVELOPE_SCHEMA)},`
  );
  for (const input of [
    ` ${canonical}`,
    `${canonical}\n`,
    reordered,
    alternateEscape,
    duplicate
  ]) {
    assert.doesNotThrow(() => JSON.parse(input));
    errorContract(() => parseCanonicalMessageEnvelopeWireV1(input));
  }
});

test("raw wire rejects malformed JSON", () => {
  for (const input of ["", "{", "[]", "null", "true"]) {
    errorContract(() => parseCanonicalMessageEnvelopeWireV1(input));
  }
});

test("all public failures use one non-sensitive error contract", () => {
  const rejectedMarker = "synthetic-rejected-value-marker";
  const input = fixture();
  input.schema = rejectedMarker;
  for (const operation of [
    () => normalizeMessageEnvelopeV1(input),
    () => serializeCanonicalMessageEnvelopeV1(input),
    () => digestCanonicalMessageEnvelopeV1(input),
    () => parseCanonicalMessageEnvelopeWireV1(rejectedMarker)
  ]) {
    errorContract(operation);
    try {
      operation();
    } catch (error) {
      assert.doesNotMatch(error.message, new RegExp(rejectedMarker));
      assert.equal(Object.keys(error).length, 0);
    }
  }
});

test("V1.28F.1 remains absent from server, BFF, config, and browser composition", async () => {
  const [server, bff, config, authEntry, authProduct] = await Promise.all([
    readFile(new URL("../scripts/hodlxxi-social-server.mjs", import.meta.url), "utf8"),
    readFile(new URL("../src/server/social-oauth-bff.mjs", import.meta.url), "utf8"),
    readFile(new URL("../src/server/social-oauth-config.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/auth-entry.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/auth-product.mjs", import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(server, /message-envelope-v128f1/);
  assert.doesNotMatch(bff, /message-envelope-v128f1|\/auth\/(?:message|messages|inbox|ciphertext)(?:[/?"']|$)/);
  assert.doesNotMatch(
    config,
    /SOCIAL_(?:MESSAGE_STORAGE|MESSAGES|INBOX|POSTGRES|DATABASE)|DATABASE_URL|POSTGRESQL|\bPG(?:HOST|PORT|DATABASE|USER|PASSWORD)\b/
  );
  assert.doesNotMatch(authEntry, /message-envelope-v128f1|src\/server/);
  assert.doesNotMatch(authProduct, /message-envelope-v128f1|src\/server/);
});

test("package manifests remain byte-identical to the V1.28E base", async () => {
  const [manifest, lock] = await Promise.all([
    readFile(new URL("../package.json", import.meta.url)),
    readFile(new URL("../package-lock.json", import.meta.url))
  ]);
  assert.equal(
    createHash("sha256").update(manifest).digest("hex"),
    "fbaf65be231ed7d2ee8fffac91611140f873b3ff8c06ad594b71c765af3dac39"
  );
  assert.equal(
    createHash("sha256").update(lock).digest("hex"),
    "bb10f1750919c068406bb04da45e4d786ce3d6f7d5326dadc759b2bb74597b39"
  );
});

test("the new module has no persistence, network, background, or startup imports", async () => {
  const source = await readFile(
    new URL("../src/server/message-envelope-v128f1.mjs", import.meta.url),
    "utf8"
  );
  const imports = [...source.matchAll(/from\s+"([^"]+)"/g)]
    .map((match) => match[1]);
  assert.deepEqual(imports, ["node:buffer", "node:crypto", "node:util/types"]);
  assert.doesNotMatch(
    source,
    /(?:node:fs|node:http|node:https|node:net|node:dgram|node:tls|postgres|\bpg\b|fetch\s*\(|XMLHttpRequest|WebSocket|setTimeout|setInterval|queueMicrotask|process\.|\.listen\s*\(|\.connect\s*\(|writeFile|appendFile|createWriteStream|worker_threads)/
  );
});
