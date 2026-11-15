import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCiphertextMailboxV1 } from "../src/server/message-ciphertext-mailbox-v1.mjs";

const fixture = JSON.parse(readFileSync(
  new URL("./fixtures/social_messaging_phase3_routing_v1.json", import.meta.url),
  "utf8"
));
const wire = fixture.envelopeWire;
const parsed = JSON.parse(wire);
const deviceHandle = parsed.recipientDeviceHandles[0];
const ctx = {
  expectedSubject: "a".repeat(64),
  viewerAccessToken: "server-only-OAuth-bearer"
};
const submit = {
  ...ctx, recipientCapability: "rc_" + "c".repeat(43), envelopeWire: wire
};
const inbox = {...ctx, deviceHandle};
const make = (directory, {send = true, read = true} = {}) =>
  createCiphertextMailboxV1({
    directory, now: () => 1234,
    authorizeSubmission: async ({envelope}) =>
      send ? {
        allowed: true, recipientPackageSnapshotId: envelope.recipientPackageSnapshotId,
        recipientDeviceHandles: [...envelope.recipientDeviceHandles],
        senderDeviceHandle: deviceHandle
      } : {allowed: false},
    authorizeInbox: async () =>
      read ? {allowed: true, deviceHandle} : {allowed: false}
  });
const temp = async (fn) => {
  const root = await mkdtemp(join(tmpdir(), "hodlxxi-mailbox-"));
  const directory = join(root, "private-inbox");
  try { await fn(directory); } finally { await rm(root, {recursive: true, force: true}); }
};

test("ciphertext is written once, can be read after new store instance, and contains no OAuth bearer", async () => {
  await temp(async directory => {
    const writer = make(directory);
    assert.deepEqual(await writer.submitForViewer(submit), {
      state: "accepted", messageId: parsed.messageId
    });
    const entries = await readdir(directory);
    assert.equal(entries.filter(x => x.endsWith(".msg")).length, 1);
    const raw = await readFile(join(directory, entries.find(x => x.endsWith(".msg"))), "utf8");
    assert.equal(JSON.parse(raw).envelopeWire, wire);
    assert.doesNotMatch(raw, /server-only-OAuth-bearer|rc_ccc/);
    const reader = make(directory);
    assert.deepEqual(await reader.listForViewer(inbox), {state: "available", messages: [wire]});
    assert.deepEqual(await writer.submitForViewer(submit), {
      state: "accepted", messageId: parsed.messageId
    });
    assert.equal((await readdir(directory)).filter(x => x.endsWith(".msg")).length, 1);
  });
});

test("failed sender-device or recipient authorization cannot persist ciphertext", async () => {
  await temp(async directory => {
    const store = make(directory, {send: false});
    await assert.rejects(store.submitForViewer(submit), /transport unavailable/);
    assert.deepEqual((await readdir(directory).catch(() => [])).filter(x => x.endsWith(".msg")), []);
  });
});

test("failed inbox ownership and another device are denied", async () => {
  await temp(async directory => {
    const writer = make(directory);
    await writer.submitForViewer(submit);
    await assert.rejects(make(directory, {read: false}).listForViewer(inbox), /transport unavailable/);
    await assert.rejects(writer.listForViewer({
      ...inbox, deviceHandle: "d_" + "z".repeat(22)
    }), /transport unavailable/);
  });
});

test("same message ID with different ciphertext is a rejected replay conflict", async () => {
  await temp(async directory => {
    const store = make(directory);
    await store.submitForViewer(submit);
    const changed = structuredClone(parsed);
    const text = changed.body.ciphertext;
    changed.body.ciphertext = (text[0] === "A" ? "B" : "A") + text.slice(1);
    const conflictingWire = JSON.stringify(changed);
    await assert.rejects(store.submitForViewer({
      ...submit, envelopeWire: conflictingWire
    }), /transport unavailable/);
    assert.deepEqual((await store.listForViewer(inbox)).messages, [wire]);
  });
});

test("malformed plaintext or missing backend authorization never writes", async () => {
  await temp(async directory => {
    const store = make(directory);
    for (const text of ['{}', "hello Bob", wire + "\n"]) {
      await assert.rejects(store.submitForViewer({...submit, envelopeWire: text}), /transport unavailable/);
    }
    assert.deepEqual((await readdir(directory).catch(() => [])).filter(x => x.endsWith(".msg")), []);
  });
});
