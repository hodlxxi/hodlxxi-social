import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const fixtureBytes = await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
  import.meta.url
));
const fixture = JSON.parse(fixtureBytes);
const vector = fixture.vector;
const unavailable = {
  name: "TypeError",
  message: "messaging device preaccepted enrollment v2 unavailable"
};
const sorted = (value) => {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sorted(value[key])])
    );
  }
  return value;
};
const canonical = (value) => JSON.stringify(sorted(value));
const changed = (source, changes) => canonical({ ...JSON.parse(source), ...changes });
const inputWith = (changes) => changed(
  vector.preacceptedEnrollmentVerificationInputWire,
  changes
);

async function loadServer(t) {
  try {
    return await import("../src/server/messaging-device-preaccepted-enrollment-v2.mjs");
  } catch (error) {
    if (
      error?.code === "ERR_MODULE_NOT_FOUND" &&
      String(error.message).includes("@noble/ed25519")
    ) {
      t.skip("blocked: exact offline @noble/ed25519 2.3.0 is absent");
      return null;
    }
    throw error;
  }
}

test("fixture size/hash and every deterministic expected artifact are fixed", () => {
  assert.equal(fixtureBytes.byteLength, 32_998);
  assert.equal(createHash("sha256").update(fixtureBytes).digest("hex"),
    "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc");
  for (const field of [
    "acceptanceId", "acceptanceIdPreimage", "acceptanceWire",
    "approvalEventId", "approvalEventIdInput", "associationCreationPreimage",
    "associationId", "associationLinkWire", "authorizationDigest",
    "enrollmentDigest", "preEnrollmentDigest",
    "preacceptedEnrollmentVerificationInputDigest"
  ]) assert.equal(typeof vector[field], "string", field);
});

test("actual BIP340 plus strict non-ZIP-215 Ed25519 verifies to an opaque brand", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const result = await server.verifyMessagingDevicePreacceptedEnrollmentV2(
    vector.preacceptedEnrollmentVerificationInputWire
  );
  assert.equal(Object.isFrozen(result), true);
  assert.notEqual(typeof result, "boolean");
  const projection = server.projectMessagingDevicePreacceptedEnrollmentV2(result);
  assert.equal(projection.authority, "not-granted");
  assert.equal(projection.acceptanceId, vector.acceptanceId);
  assert.equal(projection.acceptanceIdPreimage, vector.acceptanceIdPreimage);
  assert.equal(projection.acceptanceWire, vector.acceptanceWire);
  assert.equal(projection.approvalEventId, vector.approvalEventId);
  assert.equal(projection.approvalEventIdInput, vector.approvalEventIdInput);
  assert.equal(projection.associationCreationPreimage,
    vector.associationCreationPreimage);
  assert.equal(projection.associationId, vector.associationId);
  assert.equal(projection.associationLinkWire, vector.associationLinkWire);
  assert.equal(projection.authorizationDigest, vector.authorizationDigest);
  assert.equal(projection.enrollmentDigest, vector.enrollmentDigest);
  assert.equal(projection.inputDigest,
    vector.preacceptedEnrollmentVerificationInputDigest);
  assert.equal(projection.preEnrollmentDigest, vector.preEnrollmentDigest);
  for (const forged of [
    { ...result },
    structuredClone(result),
    Object.create(result),
    Object.freeze({ ...result }),
    new Proxy(result, {})
  ]) assert.throws(
    () => server.projectMessagingDevicePreacceptedEnrollmentV2(forged),
    unavailable
  );
});

test("each top-level and nested transcript relationship is recomputed", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const input = JSON.parse(vector.preacceptedEnrollmentVerificationInputWire);
  const context = JSON.parse(vector.verificationContextWire);
  const enrollment = JSON.parse(vector.enrollmentWire);
  const proof = JSON.parse(vector.enrollmentPhoneProofWire);
  const approval = JSON.parse(vector.approvalEventWire);
  const cases = [
    inputWith({ acceptanceId: "00".repeat(32) }),
    inputWith({ context: canonical({ ...context, subject: "11".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, deviceId: "21".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, bindingId: "66".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, associationId: "99".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, authorityEpoch: 2 }) }),
    inputWith({ enrollment: canonical({ ...enrollment,
      enrollmentChallengeId: "ed".repeat(32) }) }),
    inputWith({ enrollment: canonical({ ...enrollment,
      issuedAt: JSON.parse(vector.preEnrollmentWire).issuedAt - 1 }) }),
    inputWith({ enrollment: canonical({ ...enrollment,
      expiresAt: JSON.parse(vector.preEnrollmentWire).expiresAt + 1 }) }),
    inputWith({ phoneProof: canonical({ ...proof,
      enrollmentChallengeId: "ed".repeat(32) }) }),
    inputWith({ phoneProof: canonical({ ...proof,
      enrollmentDigest:
        "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
        "00".repeat(32) }) }),
    inputWith({ phoneProof: canonical({ ...proof,
      publicKey: "85".repeat(32) }) }),
    inputWith({ approvalEvent: canonical({ ...approval, id: "00".repeat(32) }) }),
    inputWith({ approvalEvent: canonical({ ...approval, sig: "00".repeat(64) }) }),
    inputWith({ approvalEvent: canonical({ ...approval,
      tags: [...approval.tags].reverse() }) })
  ];
  for (const [index, source] of cases.entries()) {
    await assert.rejects(
      server.verifyMessagingDevicePreacceptedEnrollmentV2(source),
      unavailable,
      String(index)
    );
  }
});

test("strict Ed25519 low-order, torsion, noncanonical point and scalar corpus is rejected", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const profile = JSON.parse(await readFile(new URL(
    "./fixtures/social_messaging_device_proof_profile_v1.json",
    import.meta.url
  )));
  const corpus = profile.adversarialCorpus;
  const proof = JSON.parse(vector.enrollmentPhoneProofWire);
  const signatures = [
    ...corpus.lowOrderPointEncodings,
    ...corpus.mixedOrderSignatureRPointEncodings,
    ...corpus.nonCanonicalPointEncodings
  ].map((point) => point + proof.signature.slice(64));
  signatures.push(proof.signature.slice(0, 64) + corpus.scalarOrderLittleEndian);
  for (const signature of signatures) {
    const source = inputWith({
      phoneProof: canonical({ ...proof, signature })
    });
    await assert.rejects(
      server.verifyMessagingDevicePreacceptedEnrollmentV2(source),
      unavailable
    );
  }
});

test("canonical/resource attacks and V1/V2 protocol substitutions are rejected", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const source = vector.preacceptedEnrollmentVerificationInputWire;
  const value = JSON.parse(source);
  const first = Object.keys(value).sort()[0];
  const approval = JSON.parse(value.approvalEvent);
  const authorization = JSON.parse(approval.content);
  const v1 = JSON.parse(await readFile(new URL(
    "./fixtures/social_device_admission_v1.json",
    import.meta.url
  )));
  const malformed = [
    " " + source,
    source + " ",
    source.replace('"version":2', '"version":\\u0032'),
    source.slice(0, -1) + `,"${first}":${canonical(value[first])}}`,
    canonical({ ...value, unknown: null }),
    canonical({ ...value, version: 1 }),
    canonical({ ...value, version: 9_007_199_254_740_992 }),
    source + "é",
    "x".repeat(24_577),
    inputWith({ approvalEvent: canonical({
      ...approval,
      tags: [["purpose", ["nested"]], ...approval.tags.slice(1)]
    }) }),
    inputWith({ approvalEvent: canonical({
      ...approval,
      content: canonical({
        ...authorization,
        context: {
          ...authorization.context,
          createdAt: { nested: authorization.context.createdAt }
        }
      })
    }) }),
    v1.vectors.enrollmentV2.inputWire
  ];
  for (const candidate of malformed) {
    await assert.rejects(
      server.verifyMessagingDevicePreacceptedEnrollmentV2(candidate),
      unavailable
    );
  }
  await assert.rejects(
    server.verifyMessagingDevicePreacceptedEnrollmentV2(value),
    unavailable
  );
  await assert.rejects(
    server.verifyMessagingDevicePreacceptedEnrollmentV2(new Proxy({}, {})),
    unavailable
  );
  const { parseMessagingDeviceVerificationInputV1 } = await import(
    "../src/server/messaging-device-verification-statement-v1.mjs"
  );
  assert.doesNotThrow(() => parseMessagingDeviceVerificationInputV1(
    v1.vectors.enrollmentV2.inputWire
  ));
  assert.throws(() => parseMessagingDeviceVerificationInputV1(
    vector.preacceptedEnrollmentVerificationInputWire
  ), {
    name: "TypeError",
    message: "messaging device verification statement unavailable"
  });
});

test("non-register and non-initial transitions are rejected without fallback", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const input = JSON.parse(vector.preacceptedEnrollmentVerificationInputWire);
  const approval = JSON.parse(input.approvalEvent);
  const authorization = JSON.parse(approval.content);
  const pre = JSON.parse(authorization.preEnrollment);
  for (const [field, replacement] of [
    ["transitionKind", "rotate"],
    ["transitionKind", "reenroll"],
    ["preEffectAssociationState", "active"],
    ["proposedAssociationVersion", 2],
    ["proposedAuthorityEpoch", 2]
  ]) {
    const alteredPre = canonical({ ...pre, [field]: replacement });
    const alteredAuthorization = canonical({
      ...authorization,
      preEnrollment: alteredPre
    });
    const alteredApproval = canonical({
      ...approval,
      content: alteredAuthorization
    });
    await assert.rejects(server.verifyMessagingDevicePreacceptedEnrollmentV2(
      canonical({ ...input, approvalEvent: alteredApproval })
    ), unavailable);
  }
});

test("module is dormant and absent from runtime, BFF, browser-entry and UI graphs", async () => {
  const moduleNames = [
    "messaging-device-preaccepted-enrollment-v2",
    "messaging-device-ed25519-key-v2",
    "mobile-device-authorization-contract-v2",
    "mobile-device-authorization-seams-v2"
  ];
  for (const relative of [
    "../src/server/social-mobile-runtime-v1.mjs",
    "../src/server/social-mobile-composition-v1.mjs",
    "../src/server/social-mobile-bff-v1.mjs",
    "../web/social-mobile-browser-v1.mjs",
    "../web/social-mobile-ui-v1.mjs"
  ]) {
    const source = await readFile(new URL(relative, import.meta.url), "utf8");
    for (const moduleName of moduleNames) {
      assert.equal(source.includes(moduleName), false, `${relative}:${moduleName}`);
    }
  }
});
