// Component integration with SYNTHETIC sessions/authorization. This does not
// exercise UBID's final device-admission owner or claim live browser acceptance.
import assert from "node:assert/strict";
import {createHash, randomBytes, webcrypto} from "node:crypto";
import {readFileSync} from "node:fs";
import {mkdtemp, readdir, readFile, rm} from "node:fs/promises";
import http from "node:http";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test from "node:test";
import {createHttpHandler} from "../scripts/hodlxxi-social-server.mjs";
import {createSocialOAuthBff} from "../src/server/social-oauth-bff.mjs";
import {createBoundedStore} from "../src/server/social-oauth-memory.mjs";
import {SESSION_COOKIE_NAME} from "../src/server/social-oauth-cookie.mjs";
import {createCiphertextMailboxV1} from "../src/server/message-ciphertext-mailbox-v1.mjs";
import {serializeCanonicalMessageEnvelopeV1} from "../src/server/message-envelope-v128f1.mjs";
import {encryptMessageEnvelope} from "../web/message-encryption-v128e.mjs";
import {decryptMessageEnvelopeV1} from "../web/message-decryption-v1.mjs";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", {value: webcrypto});
const proofWire = JSON.parse(readFileSync(new URL("./fixtures/social_messaging_device_proof_profile_v1.json", import.meta.url))).proofVector.proofWire;
const origin = "https://social.example";

async function participant(letter, handle) {
  const pair = await webcrypto.subtle.generateKey({name: "X25519"}, false, ["deriveBits"]);
  const stamp = Date.now();
  const device = {algorithm: "x25519-v1", deviceHandle: handle, expiresAt: stamp + 120_000,
    publicKey: Buffer.from(await webcrypto.subtle.exportKey("raw", pair.publicKey)).toString("hex"),
    validFrom: stamp - 60_000, version: 1};
  const evidence = {alias: "p_" + handle.slice(2), complete: true, devices: [device],
    expiresAt: stamp + 60_000, issuedAt: stamp - 10_000,
    schema: "hodlxxi.social_messaging_recipient_package.v1", source: "hodlxxi-ubid", version: 1};
  const recipientPackage = {...evidence,
    snapshotId: "sha256:" + createHash("sha256").update(JSON.stringify(evidence), "ascii").digest("hex")};
  return {subject: letter.repeat(64), sessionId: letter.repeat(43), token: "fixture-" + letter,
    capability: "rc_" + letter.toUpperCase().repeat(42) + "A", handle,
    // Structured clone models local CryptoKey persistence; no export occurs.
    privateKey: structuredClone(pair.privateKey), recipientPackage};
}

function request(port, participant, path, body, capability) {
  return new Promise((resolve, reject) => {
    const req = http.request({host: "127.0.0.1", port, path, method: "POST",
      headers: {origin, cookie: SESSION_COOKIE_NAME + "=" + participant.sessionId,
        "content-type": "application/json", "content-length": Buffer.byteLength(body),
        "x-hodlxxi-message-device-proof": proofWire,
        ...(capability ? {"x-hodlxxi-recipient-capability": capability} : {})}}, res => {
      let data = "";
      res.on("data", chunk => { data += chunk; });
      res.on("end", () => resolve({status: res.statusCode, body: JSON.parse(data)}));
      res.on("error", reject);
    });
    req.on("error", reject); req.end(body);
  });
}

test("synthetic two-party HTTP encryption, durable mailbox, restart and local decryption", async () => {
  const root = await mkdtemp(join(tmpdir(), "social-crypto-storage-"));
  const directory = join(root, "mailbox");
  const alice = await participant("a", "d_AAAAAAAAAAAAAAAAAAAAAA");
  const bob = await participant("b", "d_BBBBBBBBBBBBBBBBBBBBBA");
  const people = [alice, bob];
  const publicPeople = people.map(({privateKey, ...publicFields}) => publicFields);
  const full = new Set(people.map(p => p.subject));
  const revoked = new Set();
  const sessions = createBoundedStore({ttlSeconds: 3600, capacity: 2});
  for (const p of people) sessions.create(p.sessionId, {subject: p.subject, viewerAccessToken: p.token});
  const authorizers = {
    // Fixture authorization is intentionally independent of real UBID authority.
    async authorizeSubmission(input) {
      const sender = publicPeople.find(p => p.subject === input.expectedSubject && p.token === input.viewerAccessToken);
      const recipient = publicPeople.find(p => p.capability === input.recipientCapability);
      if (!sender || !recipient || !full.has(sender.subject) || revoked.has(sender.handle) ||
          !full.has(recipient.subject) || revoked.has(recipient.handle) ||
          input.envelope.recipientPackageSnapshotId !== recipient.recipientPackage.snapshotId ||
          input.envelope.recipientDeviceHandles.join() !== recipient.handle) return {allowed: false};
      return {allowed: true, senderDeviceHandle: sender.handle,
        recipientPackageSnapshotId: recipient.recipientPackage.snapshotId, recipientDeviceHandles: [recipient.handle]};
    },
    async authorizeInbox(input) {
      const p = publicPeople.find(p => p.subject === input.expectedSubject && p.token === input.viewerAccessToken && p.handle === input.deviceHandle);
      return {allowed: Boolean(p && full.has(p.subject) && !revoked.has(p.handle)), deviceHandle: p?.handle};
    }
  };
  let server;
  const start = async () => {
    const mailbox = createCiphertextMailboxV1({directory, ...authorizers});
    const bff = createSocialOAuthBff({config: {publicOrigin: origin}, pendingTransactions: {}, sessions,
      oauthClient: {}, messagingTransportClient: mailbox,
      authorityReader: async subject => ({valid: true, subject, status: full.has(subject) ? "full" : "limited"})});
    server = http.createServer(createHttpHandler({publicOrigin: origin, bff}));
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    return server.address().port;
  };
  const close = async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server = undefined;
  };
  try {
    let port = await start();
    const sent = [];
    for (const [sender, recipient] of [[alice, bob], [bob, alice]]) {
      const plaintext = randomBytes(24).toString("hex");
      const wire = serializeCanonicalMessageEnvelopeV1(await encryptMessageEnvelope({recipientPackage: recipient.recipientPackage, plaintext}));
      const response = await request(port, sender, "/auth/messages", wire, recipient.capability);
      assert.equal(response.status, 200);
      sent.push({sender, recipient, wire, plaintext});
    }
    await close(); port = await start();
    for (const {sender, recipient, wire, plaintext} of sent) {
      const body = JSON.stringify({deviceHandle: recipient.handle, schema: "hodlxxi.social_messaging_recipient_self_request.v1", version: 1});
      const response = await request(port, recipient, "/auth/messages/inbox", body);
      assert.equal(response.status, 200);
      assert.deepEqual(response.body.messages, [wire]);
      assert.ok(await decryptMessageEnvelopeV1({envelope: JSON.parse(wire), deviceHandle: recipient.handle, privateKey: recipient.privateKey}) === plaintext);
      assert.equal(recipient.privateKey.extractable, false);
      assert.equal((await request(port, sender, "/auth/messages", wire, recipient.capability)).status, 200);
    }
    for (const name of (await readdir(directory)).filter(n => n.endsWith(".msg"))) {
      const stored = await readFile(join(directory, name), "utf8");
      assert.ok(sent.every(p => !stored.includes(p.plaintext)));
      assert.ok(people.every(p => !stored.includes(p.token)));
    }
    full.delete(alice.subject);
    assert.equal((await request(port, alice, "/auth/messages", sent[0].wire, bob.capability)).status, 403);
    full.add(alice.subject); revoked.add(bob.handle);
    assert.equal((await request(port, bob, "/auth/messages/inbox", JSON.stringify({deviceHandle: bob.handle,
      schema: "hodlxxi.social_messaging_recipient_self_request.v1", version: 1}))).status, 503);
  } finally {
    if (server) await close();
    await rm(root, {recursive: true, force: true});
  }
});
