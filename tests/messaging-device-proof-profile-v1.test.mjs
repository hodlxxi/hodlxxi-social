import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { etc as nobleEd25519Etc } from "@noble/ed25519";
import {
  ATOMIC_CHALLENGE_OWNER,
  AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES,
  AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR,
  DEVICE_PROOF_PROFILE,
  DEVICE_PROOF_RUNTIME_ENABLED,
  ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT,
  ENROLLMENT_V2_RUNTIME_ENABLED,
  FINAL_ADMISSION_OWNER,
  FINAL_AUTHORITY_MODEL,
  createDeviceProofSigningPreimageV1,
  createDeviceProofV1,
  createEnrollmentApprovalUnsignedEventV2,
  createEnrollmentProofSigningPreimageV2,
  createEnrollmentProofV2,
  createEnrollmentV2,
  digestEnrollmentV2,
  parseDeviceProofV1,
  parseEnrollmentProofV2,
  parseEnrollmentV2,
  strictVerifyMessagingDeviceEd25519V1,
  verifyEnrollmentV2Authorization,
  verifyMessagingDeviceProofV1,
  x25519PublicKeyCommitmentV1
} from "../src/server/messaging-device-proof-profile-v1.mjs";
import {
  computeNostrEventId,
  verifyBip340Signature
} from "../web/nostr-event-verifier.mjs";
import {
  APPROVED_DEVICE_PROOF_PROFILE,
  DEVICE_ADMISSION_ENABLED,
  admitMessagingDeviceRequestV1,
  createDeviceChallengeCandidateV1,
  createDeviceRequestCandidateV1,
  inspectDeviceChallengeCandidateV1,
  parseDeviceRequestCandidateV1
} from "../src/server/messaging-device-admission-v1.mjs";

const fixtureBytes = await readFile(new URL(
  "./fixtures/social_messaging_device_proof_profile_v1.json",
  import.meta.url
));
const vectors = JSON.parse(fixtureBytes);
const proof = vectors.proofVector;
const enrollment = vectors.enrollmentVector;
const proofValue = JSON.parse(proof.proofWire);
const enrollmentValue = JSON.parse(enrollment.wire);
const enrollmentProofValue = JSON.parse(enrollment.phoneProofWire);
const canonical = (value) => JSON.stringify(
  Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]))
);
const change = (wire, changes) => canonical({ ...JSON.parse(wire), ...changes });
const denied = (call) => assert.throws(call, {
  name: "TypeError",
  message: "messaging device proof unavailable"
});
const deniedAsync = (call) => assert.rejects(call, {
  name: "TypeError",
  message: "messaging device proof unavailable"
});
const verifyProof = (changes = {}) => verifyMessagingDeviceProofV1({
  storedChallengeWire: proof.storedChallengeWire,
  actualRequestWire: proof.actualRequestWire,
  proofWire: proof.proofWire,
  expectedPublicKey: proof.publicKey,
  now: proof.now,
  ...changes
});
const approvalEvent = (changes = {}) => ({
  ...enrollment.approvalEvent,
  tags: enrollment.approvalEvent.tags.map((tag) => [...tag]),
  ...changes
});
const enrollmentAuthorizationInput = (changes = {}) => ({
  enrollmentWire: enrollment.wire,
  approvalEvents: [approvalEvent()],
  phoneProofWire: enrollment.phoneProofWire,
  authenticatedSessionSubject: enrollmentValue.subject,
  now: enrollment.now,
  ...changes
});
const verifyEnrollment = (changes = {}) =>
  verifyEnrollmentV2Authorization(enrollmentAuthorizationInput(changes));

test("independent profile and Enrollment V2 vectors are frozen and valid", async () => {
  assert.equal(
    createHash("sha256").update(fixtureBytes).digest("hex"),
    "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"
  );
  assert.equal(DEVICE_PROOF_PROFILE,
    "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1");
  assert.equal(APPROVED_DEVICE_PROOF_PROFILE, DEVICE_PROOF_PROFILE);
  assert.equal(
    createDeviceProofSigningPreimageV1(proof.storedChallengeWire, proof.publicKey),
    proof.signingPreimage
  );
  assert.deepEqual(parseDeviceProofV1(proof.proofWire), proofValue);
  assert.equal(createDeviceProofV1({
    challengeId: proofValue.challengeId,
    publicKey: proofValue.publicKey,
    signature: proofValue.signature
  }), proof.proofWire);
  const result = verifyProof();
  assert.deepEqual(result, {
    atomicChallengeConsumption: "not_implemented",
    bindingId: JSON.parse(proof.actualRequestWire).bindingId,
    bindingVersion: 1,
    canonicalStructureValidity: "valid",
    challengeDigest: "hodlxxi-social-device-challenge-v1-sha256:" +
      createHash("sha256")
        .update("HODLXXI_SOCIAL_DEVICE_CHALLENGE_DIGEST_V1\0", "ascii")
        .update(proof.storedChallengeWire, "ascii")
        .digest("hex"),
    currentDeviceKeyAssociationValidity: "not_evaluated",
    deviceId: enrollmentValue.deviceId,
    finalAdmission: "denied",
    proofProfile: DEVICE_PROOF_PROFILE,
    sessionBinding: JSON.parse(proof.actualRequestWire).sessionBinding,
    strictEd25519CryptographicValidity: "valid",
    subject: enrollmentValue.subject
  });
  assert.ok(Object.isFrozen(result));

  assert.equal(
    x25519PublicKeyCommitmentV1(enrollment.x25519PublicKey),
    enrollment.x25519PublicKeyCommitment
  );
  assert.equal(createEnrollmentV2({
    audience: enrollmentValue.audience,
    deviceId: enrollmentValue.deviceId,
    ed25519PublicKey: enrollmentValue.ed25519PublicKey,
    enrollmentChallengeId: enrollmentValue.enrollmentChallengeId,
    expiresAt: enrollmentValue.expiresAt,
    issuedAt: enrollmentValue.issuedAt,
    subject: enrollmentValue.subject,
    x25519BindingId: enrollmentValue.x25519BindingId,
    x25519BindingVersion: enrollmentValue.x25519BindingVersion,
    x25519PublicKeyCommitment: enrollmentValue.x25519PublicKeyCommitment
  }), enrollment.wire);
  assert.deepEqual(parseEnrollmentV2(enrollment.wire), enrollmentValue);
  assert.equal(digestEnrollmentV2(enrollment.wire), enrollment.digest);
  assert.equal(
    createEnrollmentProofSigningPreimageV2(enrollment.wire),
    enrollment.phoneProofSigningPreimage
  );
  assert.deepEqual(parseEnrollmentProofV2(enrollment.phoneProofWire), enrollmentProofValue);
  assert.equal(createEnrollmentProofV2({
    enrollmentChallengeId: enrollmentProofValue.enrollmentChallengeId,
    enrollmentDigest: enrollmentProofValue.enrollmentDigest,
    publicKey: enrollmentProofValue.publicKey,
    signature: enrollmentProofValue.signature
  }), enrollment.phoneProofWire);
  assert.deepEqual(
    createEnrollmentApprovalUnsignedEventV2(enrollment.wire),
    enrollment.approvalUnsignedEvent
  );
  assert.deepEqual(
    {
      content: enrollment.approvalEvent.content,
      created_at: enrollment.approvalEvent.created_at,
      kind: enrollment.approvalEvent.kind,
      tags: enrollment.approvalEvent.tags
    },
    enrollment.approvalUnsignedEvent
  );
  assert.equal(enrollment.approvalEvent.pubkey, enrollmentValue.subject);
  assert.equal(
    await computeNostrEventId(enrollment.approvalEvent, { cryptoImpl: webcrypto }),
    enrollment.approvalEvent.id
  );
  assert.equal(await verifyBip340Signature(
    enrollment.approvalEvent.pubkey,
    enrollment.approvalEvent.id,
    enrollment.approvalEvent.sig,
    { cryptoImpl: webcrypto }
  ), true);
  const enrolled = await verifyEnrollment();
  assert.equal(enrolled.canonicalStructureValidity, "valid");
  assert.equal(enrolled.externalSignerApprovalValidity, "valid");
  assert.equal(enrolled.phoneProofOfPossessionValidity, "valid");
  assert.equal(enrolled.strictEd25519CryptographicValidity, "valid");
  assert.equal(enrolled.currentDeviceKeyAssociationValidity, "not_evaluated");
  assert.equal(enrolled.atomicChallengeConsumption, "not_implemented");
  assert.equal(enrolled.finalAdmission, "denied");
});

// Each corpus entry crosses the real enrollment constructor/parser and the
// request/challenge paths. audienceJson also exercises ASCII JSON \u escapes.
for (const { id, audience, audienceJson, accepted } of vectors.audienceCorpus.cases) {
  test(`shared canonical audience corpus: ${id}`, () => {
    assert.equal(JSON.parse(audienceJson), audience);
    const { domain, profile, schema, version, ...enrollmentInput } = enrollmentValue;
    const enrollmentWire = change(enrollment.wire, { audience });
    const escapedEnrollment = enrollment.wire.replace(
      JSON.stringify(enrollmentValue.audience), audienceJson
    );
    const requestValue = JSON.parse(proof.actualRequestWire);
    const requestWire = change(proof.actualRequestWire, { audience });
    const escapedRequest = proof.actualRequestWire.replace(
      JSON.stringify(requestValue.audience), audienceJson
    );
    const context = Object.fromEntries(
      ["bindingId", "bindingVersion", "deviceId", "sessionBinding", "subject"]
        .map((field) => [field, requestValue[field]])
    );
    const options = { enabled: true };
    const challenge = JSON.parse(proof.storedChallengeWire);
    const constructor = () => createEnrollmentV2({ ...enrollmentInput, audience });
    const candidate = () => createDeviceRequestCandidateV1(
      canonical({ ...context, audience }),
      "recipient-self-read", "POST", "/auth/messaging/v1/recipient-self",
      canonical({
        deviceHandle: "d_CAgICAgICAgICAgICAgICA",
        schema: "hodlxxi.social_messaging_recipient_self_request.v1",
        version: 1
      }), options
    );
    const admissionDenied = (call) => assert.throws(call, {
      name: "TypeError", message: "messaging device admission unavailable"
    });
    if (accepted) {
      assert.equal(constructor(), enrollmentWire);
      assert.equal(parseEnrollmentV2(enrollmentWire).audience, audience);
      assert.equal(parseEnrollmentV2(escapedEnrollment).audience, audience);
      assert.equal(parseDeviceRequestCandidateV1(candidate(), options).audience, audience);
    } else {
      denied(constructor);
      denied(() => parseEnrollmentV2(enrollmentWire));
      denied(() => parseEnrollmentV2(escapedEnrollment));
      admissionDenied(candidate);
    }
    for (const wire of [requestWire, escapedRequest]) {
      const challengeWire = canonical({ ...challenge, request: wire });
      const paths = [
        () => parseDeviceRequestCandidateV1(wire, options),
        () => createDeviceChallengeCandidateV1(
          wire, challenge.challengeId, challenge.issuedAt, challenge.expiresAt, options
        ),
        () => inspectDeviceChallengeCandidateV1(challengeWire, wire, proof.now, options)
      ];
      if (accepted) {
        for (const path of paths) assert.doesNotThrow(path);
        assert.equal(createDeviceProofSigningPreimageV1(challengeWire, proof.publicKey),
          proof.signingPreimage.replace(
            JSON.stringify(proof.storedChallengeWire), JSON.stringify(challengeWire)
          ));
      } else {
        for (const path of paths) admissionDenied(path);
        denied(() => createDeviceProofSigningPreimageV1(challengeWire, proof.publicKey));
      }
    }
  });
}

test("RFC 8032 vector 1 passes the same strict primitive boundary", () => {
  const vector = vectors.rfc8032Vector1;
  assert.equal(strictVerifyMessagingDeviceEd25519V1(
    new Uint8Array(), vector.publicKey, vector.signature
  ), true);
});

test("strict verifier SHA-512 is module-owned and immutable", () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    nobleEd25519Etc,
    "sha512Sync"
  );
  assert.equal(descriptor.configurable, false);
  assert.equal(descriptor.writable, false);
  assert.equal(typeof descriptor.value, "function");
  assert.throws(() => {
    nobleEd25519Etc.sha512Sync = () => new Uint8Array(64);
  }, TypeError);
  assert.equal(strictVerifyMessagingDeviceEd25519V1(
    new Uint8Array(),
    vectors.rfc8032Vector1.publicKey,
    vectors.rfc8032Vector1.signature
  ), true);
});

test("complete pinned C2SP low-order, noncanonical and mixed-torsion corpora reject", () => {
  const corpus = vectors.adversarialCorpus;
  assert.equal(corpus.c2spCommit, "4448f2097b2daa812c91a26141f9f36c2096b9ca");
  assert.equal(corpus.c2spFileSha256,
    "b38e84caf3e7e89170ff520292dbeae421b0a794c27408ce5ce973018fe3d7f9");
  assert.equal(corpus.lowOrderPointEncodings.length, 14);
  assert.equal(corpus.nonCanonicalPointEncodings.length, 6);
  assert.equal(corpus.mixedOrderPublicPointEncodings.length, 7);
  assert.equal(corpus.mixedOrderSignatureRPointEncodings.length, 7);
  const message = new TextEncoder().encode(proof.signingPreimage);
  for (const point of [
    ...corpus.lowOrderPointEncodings,
    ...corpus.nonCanonicalPointEncodings,
    ...corpus.mixedOrderPublicPointEncodings
  ]) {
    assert.equal(
      strictVerifyMessagingDeviceEd25519V1(message, point, proofValue.signature),
      false,
      `accepted public point ${point}`
    );
  }
  const scalar = proofValue.signature.slice(64);
  for (const point of [
    ...corpus.lowOrderPointEncodings,
    ...corpus.nonCanonicalPointEncodings,
    ...corpus.mixedOrderSignatureRPointEncodings
  ]) {
    assert.equal(
      strictVerifyMessagingDeviceEd25519V1(
        message, proof.publicKey, point + scalar
      ),
      false,
      `accepted signature R ${point}`
    );
  }
});

test("identity degeneracy, noncanonical S, wrong key and signature mutation reject", () => {
  const message = new TextEncoder().encode(proof.signingPreimage);
  const identity = "01" + "00".repeat(31);
  assert.equal(strictVerifyMessagingDeviceEd25519V1(
    message, identity, identity + "00".repeat(32)
  ), false);
  const r = proofValue.signature.slice(0, 64);
  for (const scalar of [
    vectors.adversarialCorpus.scalarOrderLittleEndian,
    "ff".repeat(32)
  ]) {
    assert.equal(strictVerifyMessagingDeviceEd25519V1(
      message, proof.publicKey, r + scalar
    ), false);
  }
  assert.equal(strictVerifyMessagingDeviceEd25519V1(
    message, vectors.rfc8032Vector1.publicKey, proofValue.signature
  ), false);
  const mutated = proofValue.signature.slice(0, -1) +
    (proofValue.signature.endsWith("0") ? "1" : "0");
  assert.equal(strictVerifyMessagingDeviceEd25519V1(
    message, proof.publicKey, mutated
  ), false);
  denied(() => verifyProof({ proofWire: change(proof.proofWire, { signature: mutated }) }));
});

test("proof wire rejects alternate encodings, members, accessors and inherited input", () => {
  const candidates = [
    proof.proofWire + "\n",
    " " + proof.proofWire,
    change(proof.proofWire, { publicKey: proof.publicKey.toUpperCase() }),
    change(proof.proofWire, { publicKey: "0x" + proof.publicKey }),
    change(proof.proofWire, { publicKey: Buffer.from(proof.publicKey, "hex").toString("base64") }),
    change(proof.proofWire, { signature: proofValue.signature.toUpperCase() }),
    change(proof.proofWire, { algorithm: "ed25519" }),
    change(proof.proofWire, { profile: DEVICE_PROOF_PROFILE + ".other" }),
    change(proof.proofWire, { padding: null }),
    proof.proofWire.replace('"version":1', '"version":1,"version":1')
  ];
  for (const candidate of candidates) denied(() => parseDeviceProofV1(candidate));
  const accessor = {
    get challengeId() { assert.fail("accessor invoked"); },
    publicKey: proof.publicKey,
    signature: proofValue.signature
  };
  denied(() => createDeviceProofV1(accessor));
  denied(() => createDeviceProofV1(Object.create({
    challengeId: proofValue.challengeId,
    publicKey: proof.publicKey,
    signature: proofValue.signature
  })));
  const proxy = new Proxy({}, {
    getPrototypeOf() { assert.fail("proxy invoked"); }
  });
  denied(() => createDeviceProofV1(proxy));
});

test("every proof-bound request and challenge substitution invalidates the proof", () => {
  const request = JSON.parse(proof.actualRequestWire);
  const otherHandle = "d_" + Buffer.alloc(16, 8).toString("base64url");
  const substitutions = [
    { subject: "aa".repeat(32) },
    { sessionBinding: "bb".repeat(32) },
    { deviceId: "cc".repeat(32) },
    { bindingId: "dd".repeat(32) },
    { bindingVersion: 2 },
    { operation: "recipient-self-read", recipientHandle: otherHandle },
    { method: "GET" },
    { path: "/auth/messaging/v1/other" },
    { bodyDigest: request.bodyDigest.slice(0, -1) + "0" },
    { audience: "https://other.example" }
  ];
  for (const replacement of substitutions) {
    const actualRequestWire = canonical({ ...request, ...replacement });
    denied(() => verifyProof({ actualRequestWire }));
    const challenge = JSON.parse(proof.storedChallengeWire);
    const storedChallengeWire = canonical({ ...challenge, request: actualRequestWire });
    denied(() => verifyProof({ storedChallengeWire, actualRequestWire }));
  }
  denied(() => verifyProof({
    proofWire: change(proof.proofWire, { challengeId: "88".repeat(32) })
  }));
  denied(() => verifyProof({
    proofWire: change(proof.proofWire, { publicKey: vectors.rfc8032Vector1.publicKey }),
    expectedPublicKey: vectors.rfc8032Vector1.publicKey
  }));
});

test("challenge freshness is exact, exclusive and capped at 60 seconds", () => {
  const challenge = JSON.parse(proof.storedChallengeWire);
  assert.equal(verifyProof({ now: challenge.issuedAt }).finalAdmission, "denied");
  assert.equal(verifyProof({ now: challenge.expiresAt - 1 }).finalAdmission, "denied");
  denied(() => verifyProof({ now: challenge.issuedAt - 1 }));
  denied(() => verifyProof({ now: challenge.expiresAt }));
  denied(() => verifyProof({
    storedChallengeWire: canonical({
      ...challenge,
      expiresAt: challenge.issuedAt + 60_001
    })
  }));
});

test("Enrollment V2 rejects zero approval events", async () => {
  await deniedAsync(() => verifyEnrollment({ approvalEvents: [] }));
});

test("Enrollment V2 rejects multiple approval events", async () => {
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent(), approvalEvent()]
  }));
});

test("Enrollment V2 rejects a changed approval event ID", async () => {
  const id = enrollment.approvalEvent.id;
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({
      id: id.slice(0, -1) + (id.endsWith("0") ? "1" : "0")
    })]
  }));
});

test("Enrollment V2 rejects a changed approval event signature", async () => {
  const signature = enrollment.approvalEvent.sig;
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({
      sig: signature.slice(0, -1) + (signature.endsWith("0") ? "1" : "0")
    })]
  }));
});

test("Enrollment V2 rejects a changed approval event pubkey/signer", async () => {
  const event = approvalEvent(enrollment.alternateSignerApproval);
  assert.equal(
    await computeNostrEventId(event, { cryptoImpl: webcrypto }),
    event.id
  );
  assert.equal(await verifyBip340Signature(
    event.pubkey,
    event.id,
    event.sig,
    { cryptoImpl: webcrypto }
  ), true);
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [event]
  }));
});

test("Enrollment V2 rejects changed approval event content", async () => {
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({
      content: enrollment.approvalEvent.content + " "
    })]
  }));
});

test("Enrollment V2 rejects changed ordered approval event tags", async () => {
  const tags = enrollment.approvalEvent.tags.map((tag) => [...tag]);
  [tags[0], tags[1]] = [tags[1], tags[0]];
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({ tags })]
  }));
});

test("Enrollment V2 rejects a changed approval event kind", async () => {
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({ kind: enrollment.approvalEvent.kind + 1 })]
  }));
});

test("Enrollment V2 rejects a changed approval event created_at", async () => {
  await deniedAsync(() => verifyEnrollment({
    approvalEvents: [approvalEvent({
      created_at: enrollment.approvalEvent.created_at + 1
    })]
  }));
});

test("Enrollment V2 authorization rejects verifier injection", async () => {
  await deniedAsync(() => verifyEnrollmentV2Authorization({
    ...enrollmentAuthorizationInput(),
    verifyEvent: async (event) => event
  }));
});

test("Enrollment V2 authorization rejects crypto injection", async () => {
  await deniedAsync(() => verifyEnrollmentV2Authorization({
    ...enrollmentAuthorizationInput(),
    cryptoImpl: webcrypto
  }));
});

test("Enrollment V2 authorization rejects every unknown input member", async () => {
  await deniedAsync(() => verifyEnrollmentV2Authorization({
    ...enrollmentAuthorizationInput(),
    arbitraryUnknownInput: true
  }));
});

test("Enrollment V2 preserves exact subject binding and phone possession", async () => {
  const other = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  await deniedAsync(() => verifyEnrollment({
    authenticatedSessionSubject: other
  }));
  await deniedAsync(() => verifyEnrollment({ approvalEvents: [{ qrScan: true }] }));
  await deniedAsync(() => verifyEnrollment({ phoneProofWire: undefined }));
  const mutatedProof = change(enrollment.phoneProofWire, {
    signature: enrollmentProofValue.signature.slice(0, -1) +
      (enrollmentProofValue.signature.endsWith("0") ? "1" : "0")
  });
  await deniedAsync(() => verifyEnrollment({ phoneProofWire: mutatedProof }));
});

test("Enrollment V2 rejects subject/device/binding/key/profile/challenge substitution", async () => {
  const substitutions = [
    { subject: "aa".repeat(32) },
    { deviceId: "bb".repeat(32) },
    { x25519BindingId: "cc".repeat(32) },
    { x25519BindingVersion: 2 },
    { x25519PublicKeyCommitment:
      "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "dd".repeat(32) },
    { ed25519PublicKey: vectors.rfc8032Vector1.publicKey },
    { enrollmentChallengeId: "ee".repeat(32) },
    { profile: DEVICE_PROOF_PROFILE + ".other" },
    { audience: "https://other.example" }
  ];
  for (const replacement of substitutions) {
    const enrollmentWire = change(enrollment.wire, replacement);
    await deniedAsync(() => verifyEnrollment({ enrollmentWire }));
  }
});

test("Enrollment V2 freshness is exclusive and lifetime is capped", async () => {
  await deniedAsync(() => verifyEnrollment({ now: enrollmentValue.issuedAt - 1 }));
  await deniedAsync(() => verifyEnrollment({ now: enrollmentValue.expiresAt }));
  await deniedAsync(() => verifyEnrollment({
    enrollmentWire: change(enrollment.wire, {
      expiresAt: enrollmentValue.issuedAt + 60_001
    })
  }));
});

test("all gates remain false and final admission is impossible", () => {
  assert.equal(DEVICE_PROOF_RUNTIME_ENABLED, false);
  assert.equal(ENROLLMENT_V2_RUNTIME_ENABLED, false);
  assert.equal(DEVICE_ADMISSION_ENABLED, false);
  assert.equal(ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT, true);
  assert.equal(AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR, true);
  assert.equal(AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES, true);
  assert.equal(FINAL_AUTHORITY_MODEL, "ATOMIC_OWNER_PENDING");
  assert.equal(ATOMIC_CHALLENGE_OWNER, "PENDING");
  assert.equal(FINAL_ADMISSION_OWNER, "PENDING");
  assert.equal(verifyProof().finalAdmission, "denied");
  assert.throws(() => admitMessagingDeviceRequestV1({ proof: proof.proofWire }), {
    name: "TypeError",
    message: "messaging device admission unavailable"
  });
});

test("legacy Phase 2 and Phase 3 fixtures remain byte-identical", async () => {
  const fixtures = [
    ["social_mobile_device_authorization_v1.json",
      "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"],
    ["social_messaging_phase3_routing_v1.json",
      "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c"]
  ];
  for (const [name, expected] of fixtures) {
    const bytes = await readFile(new URL(`./fixtures/${name}`, import.meta.url));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expected);
  }
});

test("proof and enrollment modules remain absent from runtime imports", async () => {
  for (const path of [
    "../scripts/hodlxxi-social-server.mjs",
    "../src/server/social-oauth-bff.mjs",
    "../src/server/social-mobile-runtime-v1.mjs",
    "../src/server/social-mobile-composition-v1.mjs",
    "../web/auth-entry.mjs"
  ]) {
    const source = await readFile(new URL(path, import.meta.url), "utf8");
    assert.doesNotMatch(source, /messaging-device-proof-profile-v1/);
  }
});
