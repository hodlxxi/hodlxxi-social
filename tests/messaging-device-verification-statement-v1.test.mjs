import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  DEVICE_PROOF_PROFILE,
  createDeviceProofSigningPreimageV1,
  createDeviceProofV1
} from "../src/server/messaging-device-proof-profile-v1.mjs";
import {
  MAX_VERIFICATION_STATEMENT_LIFETIME_MS,
  VERIFICATION_STATEMENT_ALGORITHM,
  VERIFICATION_STATEMENT_PURPOSE,
  VERIFICATION_STATEMENT_TYPE,
  VERIFICATION_STATEMENTS_ENABLED_DEFAULT,
  createMessagingDeviceVerificationStatementSignerV1,
  digestMessagingDeviceVerificationContextV1,
  digestMessagingDeviceVerificationInputV1,
  parseMessagingDeviceVerificationContextV1,
  parseMessagingDeviceVerificationInputV1,
  produceMessagingDeviceVerificationStatementV1
} from "../src/server/messaging-device-verification-statement-v1.mjs";

const fixtureBytes = await readFile(new URL(
  "./fixtures/social_device_admission_v1.json",
  import.meta.url
));
const proofFixtureBytes = await readFile(new URL(
  "./fixtures/social_messaging_device_proof_profile_v1.json",
  import.meta.url
));
const fixture = JSON.parse(fixtureBytes);
const proofFixture = JSON.parse(proofFixtureBytes);
const enrollmentVector = fixture.vectors.enrollmentV2;
const configuration = fixture.configuration;
const on = Object.freeze({ verificationStatementsEnabled: true });
const error = {
  name: "TypeError",
  message: "messaging device verification statement unavailable"
};
const denied = (call) => assert.throws(call, error);
const deniedAsync = (call) => assert.rejects(call, error);

function recursivelySorted(value) {
  if (Array.isArray(value)) return value.map(recursivelySorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, recursivelySorted(value[key])])
    );
  }
  return value;
}

const canonical = (value) => JSON.stringify(recursivelySorted(value));
const change = (wire, changes) => canonical({ ...JSON.parse(wire), ...changes });
const decodeSegment = (value) => Buffer.from(value, "base64url").toString("ascii");

const rsaKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
let signerCalls = 0;
let lastSigningInput = null;

function signer(overrides = {}, signExact = (signingInput) => {
  signerCalls += 1;
  lastSigningInput = Buffer.from(signingInput);
  return cryptoSign("RSA-SHA256", signingInput, rsaKeys.privateKey);
}) {
  return createMessagingDeviceVerificationStatementSignerV1({
    algorithm: VERIFICATION_STATEMENT_ALGORITHM,
    audience: configuration.audience,
    clientId: configuration.clientId,
    issuer: configuration.issuer,
    kid: configuration.kid,
    purpose: VERIFICATION_STATEMENT_PURPOSE,
    servicePrincipal: configuration.servicePrincipal,
    signExact,
    ...overrides
  });
}

const primarySigner = signer();

function producerInput(contextWire, inputWire, changes = {}) {
  return {
    contextWire,
    expectedAudience: configuration.audience,
    expectedClientId: configuration.clientId,
    expectedIssuer: configuration.issuer,
    expectedPurpose: VERIFICATION_STATEMENT_PURPOSE,
    expectedServicePrincipal: configuration.servicePrincipal,
    inputWire,
    now: enrollmentVector.now,
    signer: primarySigner,
    statementLifetimeMs: 9_000,
    ...changes
  };
}

function parseStatement(statement) {
  const parts = statement.split(".");
  assert.equal(parts.length, 3);
  return {
    protectedHeader: JSON.parse(decodeSegment(parts[0])),
    protectedHeaderWire: decodeSegment(parts[0]),
    payload: JSON.parse(decodeSegment(parts[1])),
    payloadWire: decodeSegment(parts[1]),
    signature: Buffer.from(parts[2], "base64url"),
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, "ascii")
  };
}

function contextAndInput(contextWire, inputWire, contextChanges) {
  const changedContext = change(contextWire, contextChanges);
  return {
    contextWire: changedContext,
    inputWire: change(inputWire, { context: changedContext })
  };
}

function dynamicDeviceVector() {
  const ed25519 = generateKeyPairSync("ed25519");
  const publicDer = ed25519.publicKey.export({ type: "spki", format: "der" });
  const publicKey = publicDer.subarray(publicDer.length - 32).toString("hex");
  const template = fixture.vectors.ciphertextSubmit;
  const originalRequest = JSON.parse(template.actualRequestWire);
  const actualRequestWire = canonical({
    ...originalRequest,
    path: "/messaging/v1/ciphertext-submit"
  });
  const originalChallenge = JSON.parse(template.challengeWire);
  const challengeWire = canonical({
    ...originalChallenge,
    request: actualRequestWire
  });
  const signingPreimage = createDeviceProofSigningPreimageV1(
    challengeWire,
    publicKey
  );
  const signature = cryptoSign(
    null,
    Buffer.from(signingPreimage, "ascii"),
    ed25519.privateKey
  ).toString("hex");
  const proofWire = createDeviceProofV1({
    challengeId: originalChallenge.challengeId,
    publicKey,
    signature
  });
  const templateContext = JSON.parse(template.contextWire);
  const contextWire = canonical({
    ...templateContext,
    ed25519PublicKey: publicKey
  });
  const inputWire = canonical({
    actualRequest: actualRequestWire,
    approvalEvent: null,
    challenge: challengeWire,
    context: contextWire,
    proof: proofWire,
    routingRequest: template.routingRequestWire,
    schema: "hodlxxi.social_device_verification_input.v1",
    version: 1
  });
  return Object.freeze({
    actualRequestWire,
    challengeWire,
    contextWire,
    ed25519,
    inputWire,
    proofWire,
    publicKey,
    signature
  });
}

const deviceVector = dynamicDeviceVector();

test("the exact merged UBID public fixture is pinned byte-for-byte", () => {
  assert.equal(fixtureBytes.byteLength, 96_928);
  assert.equal(
    createHash("sha256").update(fixtureBytes).digest("hex"),
    "09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"
  );
  assert.equal(fixture.schema, "hodlxxi.social_device_admission_vectors.v1");
  assert.equal(fixture.version, 1);
  assert.equal(fixture.provenance.rsaAlgorithm,
    "RS256 (RSASSA-PKCS1-v1_5 with SHA-256)");
  assert.equal(fixture.publicVerificationMaterial.spkiSha256,
    "sha256:569df6a856bb51a38cabd7fca78160ad847ac3ba433af226a1810f1f351a9cce");
});

test("canonical context/input parsing and UBID digest vectors have exact parity", () => {
  const expected = {
    ciphertextSubmit: [
      "hodlxxi-social-device-verification-context-v1-sha256:8f3230a541bf5f300024c3d9437c614e845b96bf7b8e83b30dc00c9096a1f2dd",
      "hodlxxi-social-device-verification-input-v1-sha256:1613f74532bd6219406c97e5d00e7022b8ea8f44f92a79fddc75091e2e0be643"
    ],
    enrollmentV2: [
      "hodlxxi-social-device-verification-context-v1-sha256:90d69dfef296c65fcc8640dffa70ffdb35b462143cdfdfc912168bf31c3e2c05",
      "hodlxxi-social-device-verification-input-v1-sha256:daf69ef1308de544b45433db7854e6f82c99d5368bb4cd9300655fc31f7219ee"
    ],
    recipientSelfRead: [
      "hodlxxi-social-device-verification-context-v1-sha256:2f42a871279e158931c65e0333ee3e6aad4b71388931f0a268a1188b002f6396",
      "hodlxxi-social-device-verification-input-v1-sha256:f9a1fd51a714aac09b1cc008f3b47120677d8b6467e05ebdaf0f27c8ebe3c388"
    ]
  };
  for (const [name, vector] of Object.entries(fixture.vectors)) {
    const context = parseMessagingDeviceVerificationContextV1(vector.contextWire);
    const input = parseMessagingDeviceVerificationInputV1(vector.inputWire);
    assert.ok(Object.isFrozen(context));
    assert.ok(Object.isFrozen(input));
    assert.equal(input.context.wire, context.wire);
    assert.equal(digestMessagingDeviceVerificationContextV1(vector.contextWire),
      expected[name][0]);
    assert.equal(digestMessagingDeviceVerificationInputV1(vector.inputWire),
      expected[name][1]);
    assert.equal(vector.contextDigest, expected[name][0]);
    assert.equal(vector.inputDigest, expected[name][1]);
  }
});

test("UBID fixed compact statements have exact canonical bytes and valid public RS256 signatures", () => {
  const publicKey = createPublicKey(fixture.publicVerificationMaterial.spkiPem);
  for (const vector of Object.values(fixture.vectors)) {
    const parsed = parseStatement(vector.compactJws);
    assert.equal(parsed.protectedHeaderWire, vector.protectedHeaderWire);
    assert.equal(parsed.payloadWire, vector.payloadWire);
    assert.equal(parsed.signingInput.toString("ascii"),
      `${vector.protectedHeaderSegment}.${vector.payloadSegment}`);
    assert.equal(cryptoVerify(
      "RSA-SHA256", parsed.signingInput, publicKey, parsed.signature
    ), true);
  }
});

test("valid Enrollment V2 traverses real NIP-01, BIP340 and strict Ed25519 verification before RS256", async () => {
  const before = signerCalls;
  const statement = await produceMessagingDeviceVerificationStatementV1(
    producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire),
    on
  );
  assert.equal(signerCalls, before + 1);
  const parsed = parseStatement(statement);
  assert.deepEqual(parsed.protectedHeader, {
    alg: "RS256",
    kid: "social-device-verifier-rs256-v1",
    typ: "hodlxxi-social-device-verification+jws"
  });
  const fixedPayload = JSON.parse(enrollmentVector.payloadWire);
  assert.deepEqual(parsed.payload, {
    ...fixedPayload,
    jti: "d05ea33d6da82581d5ede45ce459fb6f0d94cdfbd6a1d5df6b74a2493629135c"
  });
  assert.deepEqual(lastSigningInput, parsed.signingInput);
  assert.equal(cryptoVerify(
    "RSA-SHA256", parsed.signingInput, rsaKeys.publicKey, parsed.signature
  ), true);
  assert.equal(parsed.payload.result,
    "enrollment-v2-ed25519-and-nostr-valid");
});

test("valid device request traverses the real strict non-ZIP-215 Ed25519 verifier before RS256", async () => {
  const before = signerCalls;
  const statement = await produceMessagingDeviceVerificationStatementV1(
    producerInput(deviceVector.contextWire, deviceVector.inputWire),
    on
  );
  assert.equal(signerCalls, before + 1);
  const parsed = parseStatement(statement);
  assert.equal(parsed.payload.result, "strict-ed25519-valid");
  assert.equal(parsed.payload.challengeKind, "device-request-v1");
  assert.equal(parsed.payload.contextDigest,
    digestMessagingDeviceVerificationContextV1(deviceVector.contextWire));
  assert.equal(parsed.payload.inputDigest,
    digestMessagingDeviceVerificationInputV1(deviceVector.inputWire));
  assert.equal(cryptoVerify(
    "RSA-SHA256", parsed.signingInput, rsaKeys.publicKey, parsed.signature
  ), true);
});

test("all C2SP low-order, noncanonical and mixed-torsion public points remain rejected", async () => {
  const corpus = proofFixture.adversarialCorpus;
  const candidates = [
    ...corpus.lowOrderPointEncodings,
    ...corpus.nonCanonicalPointEncodings,
    ...corpus.mixedOrderPublicPointEncodings
  ];
  for (const publicKey of candidates) {
    const { contextWire, inputWire } = contextAndInput(
      deviceVector.contextWire,
      deviceVector.inputWire,
      { ed25519PublicKey: publicKey }
    );
    const proofWire = change(deviceVector.proofWire, { publicKey });
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(contextWire, change(inputWire, { proof: proofWire })),
      on
    ));
  }
});

test("all C2SP low-order, noncanonical and mixed-torsion signature R points remain rejected", async () => {
  const corpus = proofFixture.adversarialCorpus;
  const scalar = deviceVector.signature.slice(64);
  for (const point of [
    ...corpus.lowOrderPointEncodings,
    ...corpus.nonCanonicalPointEncodings,
    ...corpus.mixedOrderSignatureRPointEncodings
  ]) {
    const proofWire = change(deviceVector.proofWire, {
      signature: point + scalar
    });
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(
        deviceVector.contextWire,
        change(deviceVector.inputWire, { proof: proofWire })
      ),
      on
    ));
  }
  const r = deviceVector.signature.slice(0, 64);
  for (const scalar of [corpus.scalarOrderLittleEndian, "ff".repeat(32)]) {
    const proofWire = change(deviceVector.proofWire, {
      signature: r + scalar
    });
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(
        deviceVector.contextWire,
        change(deviceVector.inputWire, { proof: proofWire })
      ),
      on
    ));
  }
});

test("subject, device, session, audience, challenge and attempt substitutions fail closed", async () => {
  const substitutions = [
    ["subject", "aa".repeat(32)],
    ["deviceId", "bb".repeat(32)],
    ["sessionBinding", "cc".repeat(32)],
    ["audience", "https://other.example"],
    ["challengeId", "dd".repeat(32)],
    ["bindingId", "ee".repeat(32)],
    ["bindingVersion", 2]
  ];
  for (const [field, replacement] of substitutions) {
    const changed = contextAndInput(
      deviceVector.contextWire,
      deviceVector.inputWire,
      { [field]: replacement }
    );
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(changed.contextWire, changed.inputWire),
      on
    ));
  }
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
    producerInput(
      change(deviceVector.contextWire, { attemptId: "ee".repeat(32) }),
      deviceVector.inputWire
    ),
    on
  ));
});

test("X25519 binding, Ed25519 key and profile substitutions fail closed", async () => {
  for (const changes of [
    { x25519PublicKeyCommitment:
      "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "aa".repeat(32) },
    { ed25519PublicKey: "bb".repeat(32) },
    { profile: DEVICE_PROOF_PROFILE + ".other" }
  ]) {
    const changed = contextAndInput(
      enrollmentVector.contextWire,
      enrollmentVector.inputWire,
      changes
    );
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(changed.contextWire, changed.inputWire),
      on
    ));
  }
});

test("operation, method, path and body-digest substitutions fail closed", async () => {
  const request = JSON.parse(deviceVector.actualRequestWire);
  for (const changes of [
    { operation: "recipient-self-read" },
    { method: "GET" },
    { path: "/messaging/v1/recipient-self-read" },
    { bodyDigest: request.bodyDigest.slice(0, -1) +
      (request.bodyDigest.endsWith("0") ? "1" : "0") }
  ]) {
    const actualRequest = canonical({ ...request, ...changes });
    const challenge = change(deviceVector.challengeWire, { request: actualRequest });
    const input = change(deviceVector.inputWire, {
      actualRequest,
      challenge
    });
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(deviceVector.contextWire, input),
      on
    ));
  }
});

test("expired and future-issued request proofs and Enrollment V2 challenges fail with zero skew", async () => {
  const requestChallenge = JSON.parse(deviceVector.challengeWire);
  for (const now of [requestChallenge.issuedAt - 1, requestChallenge.expiresAt]) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(deviceVector.contextWire, deviceVector.inputWire, { now }),
      on
    ));
  }
  const enrollment = JSON.parse(enrollmentVector.challengeWire);
  for (const now of [enrollment.issuedAt - 1, enrollment.expiresAt]) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, { now }),
      on
    ));
  }
});

test("wrong Nostr signer, mutated NIP-01 ID and mutated BIP340 signature never reach RS256", async () => {
  const original = JSON.parse(enrollmentVector.approvalEventWire);
  const cases = [
    proofFixture.enrollmentVector.alternateSignerApproval,
    { id: original.id.slice(0, -1) + (original.id.endsWith("0") ? "1" : "0") },
    { sig: original.sig.slice(0, -1) + (original.sig.endsWith("0") ? "1" : "0") }
  ];
  for (const changes of cases) {
    const event = canonical({
      ...original,
      ...changes,
      tags: changes.tags ?? original.tags
    });
    const input = change(enrollmentVector.inputWire, { approvalEvent: event });
    const before = signerCalls;
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(enrollmentVector.contextWire, input),
      on
    ));
    assert.equal(signerCalls, before);
  }
});

test("mutated Ed25519 request and enrollment signatures never reach RS256", async () => {
  const cases = [
    [deviceVector.contextWire, deviceVector.inputWire, deviceVector.proofWire],
    [enrollmentVector.contextWire, enrollmentVector.inputWire, enrollmentVector.proofWire]
  ];
  for (const [contextWire, inputWire, proofWire] of cases) {
    const proof = JSON.parse(proofWire);
    const mutated = change(proofWire, {
      signature: proof.signature.slice(0, -1) +
        (proof.signature.endsWith("0") ? "1" : "0")
    });
    const before = signerCalls;
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(contextWire, change(inputWire, { proof: mutated })),
      on
    ));
    assert.equal(signerCalls, before);
  }
});

test("unbranded or wrong-kid signer substitutions are rejected", async () => {
  for (const replacement of [
    { ...primarySigner, kid: "wrong-key" },
    Object.freeze({ ...primarySigner }),
    new Proxy(primarySigner, {})
  ]) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, {
        signer: replacement
      }),
      on
    ));
  }
});

test("wrong issuer, audience, client, service principal and purpose reject", async () => {
  const cases = [
    { expectedIssuer: "https://other.example" },
    { expectedAudience:
      "https://other.example/internal/v1/social/device-admission/consume" },
    { expectedClientId: "other-client" },
    { expectedServicePrincipal: "other-principal" },
    { expectedPurpose: "other-purpose" }
  ];
  for (const changes of cases) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, changes),
      on
    ));
  }
});

test("statement lifetime is positive, capped at 10000 ms and bounded by evidence expiry", async () => {
  assert.equal(MAX_VERIFICATION_STATEMENT_LIFETIME_MS, 10_000);
  for (const statementLifetimeMs of [0, 10_001, -1, 1.5, "1000", true]) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
      producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, {
        statementLifetimeMs
      }),
      on
    ));
  }
  const nearExpiry = JSON.parse(enrollmentVector.challengeWire).expiresAt - 1;
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
    producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, {
      now: nearExpiry,
      statementLifetimeMs: 2
    }),
    on
  ));
});

test("the producer defaults off and disabled construction invokes the signer zero times", async () => {
  assert.equal(VERIFICATION_STATEMENTS_ENABLED_DEFAULT, false);
  let calls = 0;
  const disabledSigner = signer({}, () => {
    calls += 1;
    assert.fail("disabled producer invoked signer");
  });
  const input = producerInput(
    enrollmentVector.contextWire,
    enrollmentVector.inputWire,
    { signer: disabledSigner }
  );
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(input));
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
    input,
    { verificationStatementsEnabled: false }
  ));
  assert.equal(calls, 0);
});

test("verifier injection and arbitrary claims, headers, booleans and timestamps are rejected", async () => {
  const additions = [
    { verifier: () => true },
    { hash: createHash },
    { verified: true },
    { admitted: true },
    { claims: { role: "full" } },
    { protectedHeader: { alg: "none" } },
    { algorithm: "none" },
    { jti: "aa".repeat(32) },
    { issuedAt: enrollmentVector.now },
    { expiresAt: enrollmentVector.now + 1 }
  ];
  for (const addition of additions) {
    await deniedAsync(() => produceMessagingDeviceVerificationStatementV1({
      ...producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire),
      ...addition
    }, on));
  }
});

test("closed inputs reject accessors, proxies, inherited members and coercion hooks", async () => {
  const accessor = producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire);
  Object.defineProperty(accessor, "contextWire", {
    enumerable: true,
    get() { assert.fail("accessor invoked"); }
  });
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(accessor, on));
  const inherited = Object.create(
    producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire)
  );
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(inherited, on));
  const proxy = new Proxy({}, {
    getPrototypeOf() { assert.fail("proxy trap invoked"); }
  });
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(proxy, on));
  const evil = { toString() { assert.fail("coercion invoked"); } };
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1(
    producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire, {
      now: evil
    }),
    on
  ));
});

test("canonical wire parsers reject unknown, duplicate, escaped, non-ASCII and alternate numeric forms", () => {
  for (const wire of [
    enrollmentVector.contextWire + "\n",
    fixture.negativeBoundaryCases.duplicateContextMember,
    fixture.negativeBoundaryCases.alternateEscapedContext,
    fixture.negativeBoundaryCases.nonAsciiContext,
    change(enrollmentVector.contextWire, { unknown: true }),
    enrollmentVector.contextWire.replace('"version":1', '"version":1.0')
  ]) denied(() => parseMessagingDeviceVerificationContextV1(wire));
  for (const wire of [
    enrollmentVector.inputWire + "\n",
    enrollmentVector.inputWire.replace('"version":1', '"version":1,"version":1'),
    change(enrollmentVector.inputWire, { verified: true }),
    "x".repeat(24_577)
  ]) denied(() => parseMessagingDeviceVerificationInputV1(wire));
});

test("the opaque signer port exposes no signing method or caller-selected byte API", async () => {
  assert.deepEqual(Object.keys(primarySigner).sort(), [
    "algorithm", "audience", "clientId", "issuer", "kid", "purpose",
    "servicePrincipal"
  ]);
  assert.equal(Object.values(primarySigner).some((value) => typeof value === "function"),
    false);
  assert.equal(Object.isFrozen(primarySigner), true);
  await deniedAsync(() => produceMessagingDeviceVerificationStatementV1({
    ...producerInput(enrollmentVector.contextWire, enrollmentVector.inputWire),
    signingInput: Buffer.from("caller-selected")
  }, on));
});

test("signer construction rejects alternate algorithms and hostile records", () => {
  denied(() => signer({ algorithm: "HS256" }));
  denied(() => signer({ algorithm: "none" }));
  denied(() => signer({ purpose: "service_client_authentication" }));
  denied(() => createMessagingDeviceVerificationStatementSignerV1({
    ...primarySigner,
    signExact: () => new Uint8Array([1]),
    jwk: {}
  }));
  const proxy = new Proxy({}, {
    ownKeys() { assert.fail("proxy trap invoked"); }
  });
  denied(() => createMessagingDeviceVerificationStatementSignerV1(proxy));
});

test("no participant or device private material exists in the UBID public fixture", () => {
  const source = fixtureBytes.toString("utf8");
  assert.doesNotMatch(source,
    /-----BEGIN (?:RSA )?PRIVATE KEY-----|privateKey|secretKey|participantPrivateKey|seed|mnemonic/);
  assert.equal(fixture.provenance.description,
    "Offline synthetic public contract vectors. The RSA key was generated independently in memory solely to sign these fixed bytes; no private key was serialized or retained.");
});

test("producer remains absent from runtime, browser and BFF import graphs", async () => {
  const paths = [
    "../scripts/hodlxxi-social-server.mjs",
    "../src/server/social-mobile-runtime-v1.mjs",
    "../src/server/social-mobile-composition-v1.mjs",
    "../src/server/social-oauth-bff.mjs",
    "../web/auth-entry.mjs"
  ];
  for (const path of paths) {
    const source = await readFile(new URL(path, import.meta.url), "utf8");
    assert.doesNotMatch(source, /messaging-device-verification-statement-v1/);
  }
});

test("producer source contains no filesystem, network, database, socket, HTTP or key-loading I/O", async () => {
  const source = await readFile(new URL(
    "../src/server/messaging-device-verification-statement-v1.mjs",
    import.meta.url
  ), "utf8");
  assert.doesNotMatch(source,
    /node:(?:fs|net|http|https)|postgres|redis|socket|fetch\s*\(|readFile|openFile|createPrivateKey|PRIVATE KEY|process\.env|WebSocket/);
  assert.doesNotMatch(source, /admitMessagingDeviceRequestV1|currentFull\s*:\s*true/);
});

test("existing proof-profile and Phase 2/Phase 3 fixtures remain byte-identical", async () => {
  const expected = [
    ["social_messaging_device_proof_profile_v1.json",
      "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"],
    ["social_messaging_device_admission_v1.json",
      "9456c9d70dc4f0db4a417a330a94d969fd0be49bf75e2e9b797a6b3a9dd3d6b7"],
    ["social_mobile_device_authorization_v1.json",
      "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"],
    ["social_messaging_phase3_routing_v1.json",
      "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c"]
  ];
  for (const [name, digest] of expected) {
    const bytes = await readFile(new URL(`./fixtures/${name}`, import.meta.url));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), digest);
  }
});

test("fixed authority non-claims remain explicit constants and statement semantics", () => {
  assert.equal(VERIFICATION_STATEMENT_ALGORITHM, "RS256");
  assert.equal(VERIFICATION_STATEMENT_TYPE,
    "hodlxxi-social-device-verification+jws");
  assert.equal(VERIFICATION_STATEMENT_PURPOSE,
    "social_device_cryptographic_verification_v1");
  assert.equal(VERIFICATION_STATEMENTS_ENABLED_DEFAULT, false);
});
