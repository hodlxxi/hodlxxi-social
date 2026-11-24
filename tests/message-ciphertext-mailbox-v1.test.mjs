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
const deviceProofWire = JSON.parse(readFileSync(new URL("./fixtures/social_messaging_device_proof_profile_v1.json", import.meta.url), "utf8")).proofVector.proofWire;
const wire = fixture.envelopeWire;
const parsed = JSON.parse(wire);
const deviceHandle = parsed.recipientDeviceHandles[0];
const ctx = {
  expectedSubject: "a".repeat(64),
  viewerAccessToken: "server-only-OAuth-bearer",
  deviceProofWire
};
const submit = {
  ...ctx, recipientCapability: "rc_" + "c".repeat(43), envelopeWire: wire
};
const inbox = {...ctx, deviceHandle, requestWire: JSON.stringify({deviceHandle, schema: "hodlxxi.social_messaging_recipient_self_request.v1", version: 1})};
const make = (directory, {send = true, read = true, maximumRecords} = {}) =>
  createCiphertextMailboxV1({
    directory, now: () => 1234, ...(maximumRecords === undefined ? {} : {maximumRecords}),
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

test("bare device handles and malformed device proofs cannot reach an authorizer", async () => {
  await temp(async directory => {
    let calls = 0;
    const store = createCiphertextMailboxV1({directory,
      authorizeSubmission: async () => { calls += 1; throw Error(); },
      authorizeInbox: async () => { calls += 1; throw Error(); }});
    for (const proof of [undefined, "{}", deviceProofWire + "\n"]) {
      await assert.rejects(store.submitForViewer({...submit, deviceProofWire: proof}));
      await assert.rejects(store.listForViewer({...inbox, deviceProofWire: proof}));
    }
    assert.equal(calls, 0);
  });
});

test("concurrent store instances enforce a fixed quota and exact retries after restart", async () => {
  await temp(async directory => {
    const stores = Array.from({length: 8}, () => make(directory, {maximumRecords: 2}));
    const results = await Promise.all(stores.map(store => store.submitForViewer(submit)));
    assert.ok(results.every(result => result.messageId === parsed.messageId));
    const message = structuredClone(parsed);
    message.messageId = "m_" + "A".repeat(43);
    const second = {...submit, envelopeWire: JSON.stringify(message)};
    await stores[0].submitForViewer(second);
    const third = structuredClone(message);
    third.messageId = "m_" + "B".repeat(42) + "A";
    await assert.rejects(stores[1].submitForViewer({...submit, envelopeWire: JSON.stringify(third)}));
    assert.equal((await readdir(directory)).filter(name => name.endsWith(".msg")).length, 2);
    const restarted = make(directory, {maximumRecords: 2});
    assert.deepEqual(await restarted.submitForViewer(submit), results[0]);
    assert.equal((await restarted.listForViewer(inbox)).messages.length, 2);
  });
});
