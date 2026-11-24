import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonical } from "../web/social-mobile-protocol-v1.mjs";
import { produceRegisteredDeviceSessionStatementV1 } from "../src/server/registered-device-session-statement-v1.mjs";

const fixture = JSON.parse(await readFile(new URL("./fixtures/social_registered_device_session_v1.json", import.meta.url)));
const c = JSON.parse(fixture.challengeWire);
const input = { ...fixture, issuer:c.issuer, audience:c.audience, clientId:c.clientId, contextCommitment:c.contextCommitment, now:c.issuedAt };
test("statement signs exact domain and proof only after strict cryptographic verification", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength:2048 });
  const kid = "synthetic-key", schema = "hodlxxi.social_registered_device_session_statement.v1";
  const statement = JSON.parse(produceRegisteredDeviceSessionStatementV1(input, { kid, privateKey }));
  assert.equal(statement.schema, schema);
  assert.equal(statement.kid, kid);
  const preimage = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_STATEMENT_V1\0" + canonical({
    challenge: input.challengeWire, proof: input.proofWire, kid, schema
  });
  assert.equal(verify("RSA-SHA256", Buffer.from(preimage, "ascii"), publicKey, Buffer.from(statement.signature,"hex")), true);
  for (const altered of [
    { ...input, now:c.expiresAt },
    { ...input, contextCommitment:"aa".repeat(32) },
    { ...input, proofWire:canonical({...JSON.parse(input.proofWire), signature:"00".repeat(64)}) }
  ]) assert.throws(() => produceRegisteredDeviceSessionStatementV1(altered, {kid, privateKey}), /registered device statement unavailable/);
});
