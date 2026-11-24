import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import {
  REGISTERED_DEVICE_SESSION_RUNTIME_ENABLED,
  parseRegisteredDeviceSessionChallengeV1,
  registeredDeviceSessionSigningPreimageV1,
  createRegisteredDeviceSessionProofWireV1
} from "../web/registered-device-session-v1.mjs";
import { verifyRegisteredDeviceSessionProofV1 } from "../src/server/registered-device-session-proof-v1.mjs";

const { challengeWire, proofWire } = JSON.parse(await readFile(new URL(
  "./fixtures/social_registered_device_session_v1.json", import.meta.url
)));
const c = JSON.parse(challengeWire);
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
const expected = { challengeWire, proofWire, issuer: c.issuer, audience: c.audience, clientId: c.clientId,
  contextCommitment: c.contextCommitment, now: c.issuedAt };

test("cross-language vector verifies strictly, but does not enable session issuance", () => {
  assert.deepEqual(parseRegisteredDeviceSessionChallengeV1(challengeWire), c);
  assert.equal(verifyRegisteredDeviceSessionProofV1(expected), true);
  assert.equal(REGISTERED_DEVICE_SESSION_RUNTIME_ENABLED, false);
});
test("context, time, exact bytes, device, association and signature mismatches deny", () => {
  for (const changes of [
    { now: c.issuedAt - 1 }, { now: c.expiresAt }, { contextCommitment: "aa".repeat(32) },
    { issuer: c.audience }, { clientId: "other" }, { challengeWire: challengeWire + " " },
    { challengeWire: canonical({ ...c, deviceId: "99".repeat(32) }) },
    { challengeWire: canonical({ ...c, authorityEpoch: 2 }) },
    { challengeWire: canonical({ ...c, domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1" }) },
    { proofWire: canonical({ ...JSON.parse(proofWire), signature: "00".repeat(64) }) }
  ]) assert.equal(verifyRegisteredDeviceSessionProofV1({ ...expected, ...changes }), false);
});
test("browser WebCrypto generates a valid new domain proof with a non-extractable private key", async () => {
  const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  assert.equal(keys.privateKey.extractable, false);
  const ed25519PublicKey = Buffer.from(await webcrypto.subtle.exportKey("raw", keys.publicKey)).toString("hex");
  const wire = canonical({ ...c, ed25519PublicKey });
  const sig = await webcrypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, registeredDeviceSessionSigningPreimageV1(wire));
  const proof = createRegisteredDeviceSessionProofWireV1(wire, Buffer.from(sig).toString("hex"));
  assert.equal(verifyRegisteredDeviceSessionProofV1({ ...expected, challengeWire: wire, proofWire: proof }), true);
});
