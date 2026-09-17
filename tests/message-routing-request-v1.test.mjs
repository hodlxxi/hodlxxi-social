import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createMessageRoutingRequestV1, MAX_MESSAGE_ROUTING_REQUEST_BYTES } from "../src/server/message-routing-request-v1.mjs";
import { normalizeMessagingRecipientPackage } from "../src/server/ubid-messaging-recipient-client.mjs";
import { parseCanonicalMessageEnvelopeWireV1 } from "../src/server/message-envelope-v128f1.mjs";

const fixtureBytes = await readFile(new URL("./fixtures/social_messaging_phase3_routing_v1.json", import.meta.url));
const fixture = JSON.parse(fixtureBytes);
const enabled = { enabled: true };
const denied = (wire, options = enabled) => assert.throws(
  () => createMessageRoutingRequestV1(wire, options),
  { name: "TypeError", message: "message routing unavailable" }
);

test("exact shared UBID package and V1.28F.1 wire produce the frozen UBID request", () => {
  assert.equal(createHash("sha256").update(fixtureBytes).digest("hex"), "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c");
  const pkg = normalizeMessagingRecipientPackage(fixture.recipientPackage, { expectedAlias: fixture.recipientPackage.alias });
  const envelope = parseCanonicalMessageEnvelopeWireV1(fixture.envelopeWire);
  assert.equal(envelope.recipientPackageSnapshotId, pkg.snapshotId);
  assert.deepEqual(envelope.recipientDeviceHandles, pkg.devices.map(device => device.deviceHandle));
  assert.equal(createMessageRoutingRequestV1(fixture.envelopeWire, enabled), fixture.routingRequest);
  assert.equal(createMessageRoutingRequestV1(Buffer.from(fixture.envelopeWire), enabled), fixture.routingRequest);
  const digest = createHash("sha256").update("HODLXXI_SOCIAL_MESSAGE_ENVELOPE_DIGEST_V1\0", "ascii").update(fixture.envelopeWire, "ascii").digest("hex");
  assert.equal(fixture.envelopeDigest, `hodlxxi-social-message-envelope-v1-sha256:${digest}`);
  const request = JSON.parse(fixture.routingRequest);
  assert.deepEqual(Object.keys(request), ["envelopeDigest", "messageId", "recipientDeviceHandles", "recipientPackageSnapshotId", "schema", "version"]);
  for (const excluded of [pkg.alias, pkg.devices[0].publicKey, envelope.body.ciphertext, envelope.keyWraps[0].ciphertext]) {
    assert.equal(fixture.routingRequest.includes(excluded), false);
  }
});

test("default-off and non-boolean flags provide no request", () => {
  denied(fixture.envelopeWire, {});
  for (const enabled of [false, undefined, null, 1, "true", "false"]) denied(fixture.envelopeWire, { enabled });
  assert.throws(() => createMessageRoutingRequestV1(fixture.envelopeWire), /message routing unavailable/);
  for (const options of [null, true, Object.create({ enabled: true }),
    { get enabled() { assert.fail("gate must not execute an accessor"); } },
    new Proxy({ enabled: true }, { getOwnPropertyDescriptor() { assert.fail("gate must not inspect a proxy"); } })]) {
    denied(fixture.envelopeWire, options);
  }
});

test("wire framing and exact envelope validation cannot be bypassed by projection", () => {
  for (const wire of [JSON.parse(fixture.envelopeWire), " " + fixture.envelopeWire, fixture.envelopeWire + "\n",
    fixture.envelopeWire.replace('"version":1', '"version":1,"version":1'),
    fixture.envelopeWire.replace('"version":1', '"version":1,"plaintext":true'),
    " ".repeat(32769), new Uint8Array([255]), "{}"] ) denied(wire);
});

test("an inherited descriptor value cannot enable an accessor option", () => {
  const options = { get enabled() { assert.fail("gate must not execute an accessor"); } };
  const original = Object.getOwnPropertyDescriptor(Object.prototype, "value");
  Object.defineProperty(Object.prototype, "value", { value: true, configurable: true });
  try {
    denied(fixture.envelopeWire, options);
  } finally {
    delete Object.prototype.value;
    if (original) Object.defineProperty(Object.prototype, "value", original);
  }
});

test("projection rejects a handle with noncanonical base64 pad bits", () => {
  const value = JSON.parse(fixture.envelopeWire);
  const original = value.recipientDeviceHandles[0];
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const alternate = original.slice(0, -1) + alphabet[alphabet.indexOf(original.at(-1)) + 1];
  value.recipientDeviceHandles[0] = alternate;
  value.keyWraps[0].deviceHandle = alternate;
  denied(JSON.stringify(value));
});

test("maximum 16-device request stays bounded and binds every handle", () => {
  const value = JSON.parse(fixture.envelopeWire);
  value.recipientDeviceHandles = Array.from({ length: 16 }, (_, i) => `d_${Buffer.alloc(16, i).toString("base64url")}`).sort();
  value.keyWraps = value.recipientDeviceHandles.map(deviceHandle => ({ ...value.keyWraps[0], deviceHandle }));
  const request = createMessageRoutingRequestV1(JSON.stringify(value), enabled);
  assert.ok(Buffer.byteLength(request) <= MAX_MESSAGE_ROUTING_REQUEST_BYTES);
  assert.deepEqual(JSON.parse(request).recipientDeviceHandles, value.recipientDeviceHandles);
  value.keyWraps.pop();
  denied(JSON.stringify(value));
});

test("ciphertext change changes the digest without changing message identity", () => {
  const value = JSON.parse(fixture.envelopeWire);
  value.body.ciphertext = Buffer.alloc(97, 0xa5).toString("base64url");
  const request = JSON.parse(createMessageRoutingRequestV1(JSON.stringify(value), enabled));
  assert.equal(request.messageId, JSON.parse(fixture.routingRequest).messageId);
  assert.notEqual(request.envelopeDigest, fixture.envelopeDigest);
});

test("new projection stays outside server and authenticated browser composition", async () => {
  for (const path of ["../scripts/hodlxxi-social-server.mjs", "../src/server/social-oauth-bff.mjs", "../web/auth-entry.mjs"]) {
    assert.doesNotMatch(await readFile(new URL(path, import.meta.url), "utf8"), /message-routing-request-v1/);
  }
});
