import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import test from "node:test";

import { encryptMessageEnvelope } from "../web/message-encryption-v128e.mjs";
import { decryptMessageEnvelopeV1 } from "../web/message-decryption-v1.mjs";
import { serializeCanonicalMessageEnvelopeV1 } from "../src/server/message-envelope-v128f1.mjs";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const handles = ["d_AAAAAAAAAAAAAAAAAAAAAA", "d_BBBBBBBBBBBBBBBBBBBBBA"];
const text = "Телефон и планшет читают одно зашифрованное письмо ₿";

async function example() {
  const now = Date.now();
  const pairs = await Promise.all(handles.map(() => webcrypto.subtle.generateKey(
    { name: "X25519" }, false, ["deriveBits"]
  )));
  const devices = await Promise.all(pairs.map(async (pair, index) => ({
    deviceHandle: handles[index],
    algorithm: "x25519-v1",
    version: 1,
    publicKey: Buffer.from(await webcrypto.subtle.exportKey("raw", pair.publicKey)).toString("hex"),
    validFrom: now - 60_000,
    expiresAt: now + 300_000
  })));
  const recipientPackage = {
    schema: "hodlxxi.social_messaging_recipient_package.v1",
    version: 1,
    source: "hodlxxi-ubid",
    snapshotId: "",
    complete: true,
    alias: "p_KHcJHzAgVKtH830W3gJGIg",
    issuedAt: now - 10_000,
    expiresAt: now + 60_000,
    devices
  };
  const evidence = {
    alias: recipientPackage.alias,
    complete: true,
    devices: devices.map((device) => ({
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
    version: 1
  };
  recipientPackage.snapshotId = `sha256:${createHash("sha256")
    .update(JSON.stringify(evidence), "ascii").digest("hex")}`;
  const envelope = await encryptMessageEnvelope({ recipientPackage, plaintext: text });
  return { envelope, pairs };
}

function input(envelope, pair, index = 0) {
  return { envelope, deviceHandle: handles[index], privateKey: pair.privateKey };
}

const mustDeny = async (value) => assert.rejects(
  decryptMessageEnvelopeV1(value),
  (error) => error?.message === "message decryption unavailable"
);

test("a phone and tablet each decrypt the real sender envelope with their own private key", async () => {
  const { envelope, pairs } = await example();
  const received = JSON.parse(serializeCanonicalMessageEnvelopeV1(envelope));
  assert.equal(await decryptMessageEnvelopeV1(input(received, pairs[0])), text);
  assert.equal(await decryptMessageEnvelopeV1(input(received, pairs[1], 1)), text);
  assert.equal(pairs[0].privateKey.extractable, false);
  assert.equal(pairs[1].privateKey.extractable, false);
});

test("another device, an incorrect handle, and an extractable key cannot decrypt", async () => {
  const { envelope, pairs } = await example();
  const outsider = await webcrypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  await mustDeny(input(envelope, outsider));
  await mustDeny(input(envelope, pairs[1]));
  await mustDeny({ ...input(envelope, pairs[0]), deviceHandle: "d_CCCCCCCCCCCCCCCCCCCCCC" });
  const extractable = await webcrypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  await mustDeny(input(envelope, extractable));
});

test("modified authenticated body, header, wrap and handle ordering all deny", async () => {
  const { envelope, pairs } = await example();
  const tamper = (mutate) => {
    const copy = structuredClone(envelope);
    mutate(copy);
    return input(copy, pairs[0]);
  };
  await mustDeny(tamper((copy) => { copy.body.ciphertext =
    (copy.body.ciphertext[0] === "A" ? "B" : "A") + copy.body.ciphertext.slice(1); }));
  await mustDeny(tamper((copy) => { copy.body.nonce =
    (copy.body.nonce[0] === "A" ? "B" : "A") + copy.body.nonce.slice(1); }));
  await mustDeny(tamper((copy) => { copy.messageId = "m_" + "A".repeat(43); }));
  await mustDeny(tamper((copy) => { copy.recipientPackageSnapshotId = "sha256:" + "a".repeat(64); }));
  await mustDeny(tamper((copy) => { copy.keyWraps[0].ciphertext =
    (copy.keyWraps[0].ciphertext[0] === "A" ? "B" : "A") + copy.keyWraps[0].ciphertext.slice(1); }));
  await mustDeny(tamper((copy) => { copy.recipientDeviceHandles.reverse(); }));
  await mustDeny(tamper((copy) => { copy.keyWraps.reverse(); }));
});

test("noncanonical base64 and unexpected fields or accessors deny", async () => {
  const { envelope, pairs } = await example();
  const altered = structuredClone(envelope);
  altered.keyWraps[0].enc += "=";
  await mustDeny(input(altered, pairs[0]));
  const extra = structuredClone(envelope);
  extra.rawSubject = "private";
  await mustDeny(input(extra, pairs[0]));
  const accessor = structuredClone(envelope);
  Object.defineProperty(accessor.body, "ciphertext", { get: () => envelope.body.ciphertext });
  await mustDeny(input(accessor, pairs[0]));
  const sparse = structuredClone(envelope);
  delete sparse.keyWraps[0];
  await mustDeny(input(sparse, pairs[0]));
  const duplicated = structuredClone(envelope);
  duplicated.recipientDeviceHandles[1] = duplicated.recipientDeviceHandles[0];
  await mustDeny(input(duplicated, pairs[0]));
});

test("the decryption input is closed and does not accept sender-selected authority", async () => {
  const { envelope, pairs } = await example();
  await mustDeny({ ...input(envelope, pairs[0]), authorized: true });
  await mustDeny({ ...input(envelope, pairs[0]), privateKey: null });
  await mustDeny({ ...input(envelope, pairs[0]), envelope: null });
});
