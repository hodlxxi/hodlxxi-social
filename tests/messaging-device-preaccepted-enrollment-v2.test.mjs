import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Same-process mutation cases below are non-exhaustive, non-normative
// defense-in-depth regressions for the exact hooks exercised. Arbitrary code
// mutating the trusted Node process is process compromise, not a supported
// security boundary or a condition these tests add to commit readiness.

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
const sameProofProbeEnvironment =
  "HODLXXI_SOCIAL_SAME_PROOF_FRESH_PROBE";

async function executeSameProofFreshProbe(mode) {
  const {
    createHash: probeCreateHash,
    createPublicKey,
    verify: nativeVerify,
    webcrypto
  } = await import("node:crypto");
  const { CURVE, Point, verify: nobleVerify } = await import(
    "@noble/ed25519"
  );
  const profile = await import(
    "../src/server/messaging-device-proof-profile-v1.mjs"
  );
  const preaccepted = await import(
    "../src/server/messaging-device-preaccepted-enrollment-v2.mjs"
  );
  const producer = await import(
    "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs"
  );
  const statementFixture = JSON.parse(await readFile(new URL(
    "./fixtures/social_preaccepted_enrollment_verification_statement_v2.json",
    import.meta.url
  )));
  const statementVector = statementFixture.vector;
  const configuration = statementFixture.configuration;
  const deadlines = statementFixture.deadlines;
  const probeEnabled = Object.freeze({
    preacceptedEnrollmentVerificationStatementsV2Enabled: true
  });
  const sourceInput = JSON.parse(
    vector.preacceptedEnrollmentVerificationInputWire
  );
  const sourcePhoneProof = JSON.parse(sourceInput.phoneProof);
  const originalApply = Reflect.apply;
  const equal = (left, right) => {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) {
      if (left[index] !== right[index]) return false;
    }
    return true;
  };
  const concatenate = (...parts) => {
    const output = new Uint8Array(parts.reduce(
      (length, part) => length + part.length,
      0
    ));
    let offset = 0;
    for (const part of parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  };
  const bytesToLittleEndian = (bytes) => {
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index -= 1) {
      value = (value << 8n) | BigInt(bytes[index]);
    }
    return value;
  };
  const littleEndian32 = (source) => {
    const bytes = new Uint8Array(32);
    let value = source;
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number(value & 255n);
      value >>= 8n;
    }
    return bytes;
  };
  const produce = async (inputWire, contextWire) => {
    let signerCalls = 0;
    const signingPort = producer
      .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2({
        algorithm:
          producer.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
        audience: configuration.audience,
        clientId: configuration.clientId,
        issuer: configuration.issuer,
        kid: configuration.kid,
        purpose:
          producer.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
        servicePrincipal: configuration.servicePrincipal,
        signExact() {
          signerCalls += 1;
          return Buffer.from(statementVector.signature, "base64url");
        }
      });
    try {
      const result = await producer
        .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2({
          approverSessionExpiresAtMs: deadlines.approverSessionExpiresAtMs,
          contextWire,
          expectedAlgorithm:
            producer.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
          expectedAudience: configuration.audience,
          expectedClientId: configuration.clientId,
          expectedIssuer: configuration.issuer,
          expectedKid: configuration.kid,
          expectedPurpose:
            producer.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
          expectedServicePrincipal: configuration.servicePrincipal,
          fullExpiresAtMs: deadlines.fullExpiresAtMs,
          inputWire,
          now: deadlines.now,
          phoneSessionExpiresAtMs: deadlines.phoneSessionExpiresAtMs,
          signer: signingPort,
          statementLifetimeMs: 9_000,
          x25519BindingExpiresAtMs: deadlines.x25519BindingExpiresAtMs
        }, probeEnabled);
      return {
        accepted: true,
        signerCalls,
        statementExact: result === statementVector.compactJws
      };
    } catch {
      return { accepted: false, signerCalls };
    }
  };

  if (mode === "combined-gpows-own-iterator") {
    const message = new TextEncoder().encode(
      vector.enrollmentPhoneProofSigningPreimage
    );
    const authenticSignatureBytes = new Uint8Array(
      Buffer.from(sourcePhoneProof.signature, "hex")
    );
    const authenticR = sourcePhoneProof.signature.slice(0, 64);
    const alternateSignatureHex = authenticR + "02" + "00".repeat(31);
    const alternateSignatureBytes = new Uint8Array(
      Buffer.from(alternateSignatureHex, "hex")
    );
    const publicKeyBytes = new Uint8Array(
      Buffer.from(sourcePhoneProof.publicKey, "hex")
    );
    const publicPoint = Point.fromHex(publicKeyBytes, false);
    const signaturePoint = Point.fromHex(authenticR, false);
    const challengeHash = probeCreateHash("sha512")
      .update(Buffer.from(authenticR, "hex"))
      .update(Buffer.from(sourcePhoneProof.publicKey, "hex"))
      .update(message)
      .digest();
    let challenge = bytesToLittleEndian(challengeHash) % CURVE.n;
    const target = signaturePoint.add(
      publicPoint.multiply(challenge, false)
    );

    const pushDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      "push"
    );
    let pushCalls = 0;
    let cacheSubstitutions = 0;
    let primed;
    try {
      Object.defineProperty(Array.prototype, "push", {
        ...pushDescriptor,
        value(...items) {
          pushCalls += 1;
          if (pushCalls === 2 && items.length === 1) {
            cacheSubstitutions += 1;
            return originalApply(pushDescriptor.value, this, [target]);
          }
          return originalApply(pushDescriptor.value, this, items);
        }
      });
      primed = Point.BASE.multiply(2n, false);
    } finally {
      Object.defineProperty(Array.prototype, "push", pushDescriptor);
    }

    const rawAlternateAccepted = nobleVerify(
      alternateSignatureBytes,
      message,
      publicKeyBytes,
      { zip215: false }
    );
    const baselineAlternateAccepted =
      profile.strictVerifyMessagingDeviceEd25519V1(
        message,
        sourcePhoneProof.publicKey,
        alternateSignatureHex
      );
    const alternateInputWire = canonical({
      ...sourceInput,
      phoneProof: canonical({
        ...sourcePhoneProof,
        signature: alternateSignatureHex
      })
    });
    const alternateProducer = await produce(
      alternateInputWire,
      vector.verificationContextWire
    );

    const uint8ArrayPrototype = Uint8Array.prototype;
    const ownIteratorDescriptor = Object.getOwnPropertyDescriptor(
      uint8ArrayPrototype,
      Symbol.iterator
    );
    const inheritedIterator = Object.getPrototypeOf(
      uint8ArrayPrototype
    )[Symbol.iterator];
    let iteratorCalls = 0;
    let signatureSubstitutions = 0;
    let primitiveAcceptedWithAlternateBytes;
    let producerWithAlternateBytes;
    try {
      Object.defineProperty(uint8ArrayPrototype, Symbol.iterator, {
        configurable: true,
        enumerable: false,
        writable: true,
        value() {
          iteratorCalls += 1;
          let targeted = this.length === authenticSignatureBytes.length;
          for (
            let index = 0;
            targeted && index < authenticSignatureBytes.length;
            index += 1
          ) {
            if (this[index] !== authenticSignatureBytes[index]) {
              targeted = false;
            }
          }
          if (targeted) signatureSubstitutions += 1;
          return originalApply(
            inheritedIterator,
            targeted ? alternateSignatureBytes : this,
            []
          );
        }
      });
      primitiveAcceptedWithAlternateBytes =
        profile.strictVerifyMessagingDeviceEd25519V1(
          message,
          sourcePhoneProof.publicKey,
          sourcePhoneProof.signature
        );
      producerWithAlternateBytes = await produce(
        vector.preacceptedEnrollmentVerificationInputWire,
        vector.verificationContextWire
      );
    } finally {
      if (ownIteratorDescriptor === undefined) {
        delete uint8ArrayPrototype[Symbol.iterator];
      } else {
        Object.defineProperty(
          uint8ArrayPrototype,
          Symbol.iterator,
          ownIteratorDescriptor
        );
      }
    }
    return {
      alternateProducer,
      baselineAlternateAccepted,
      cacheSubstitutions,
      iteratorHookObserved: iteratorCalls > 0,
      ownIteratorOriginallyAbsent: ownIteratorDescriptor === undefined,
      primedValueEqualsTarget: primed.equals(target),
      primitiveAcceptedWithAlternateBytes,
      producerWithAlternateBytes,
      pushCalls,
      rawAlternateAccepted,
      signatureSubstitutions
    };
  }

  if (mode === "mixed-torsion-producer") {
    const authorization = await import(
      "../web/mobile-device-authorization-contract-v2.mjs"
    );
    const bytesToBigEndian = (bytes) => {
      let value = 0n;
      for (let index = 0; index < bytes.length; index += 1) {
        value = (value << 8n) | BigInt(bytes[index]);
      }
      return value;
    };
    const bigEndian32 = (value) => Buffer.from(
      value.toString(16).padStart(64, "0"),
      "hex"
    );
    const sha256 = (...parts) => {
      const hash = probeCreateHash("sha256");
      for (const part of parts) hash.update(part);
      return hash.digest();
    };
    const domainSha256Hex = (domain, wire) => probeCreateHash("sha256")
      .update(domain + "\0", "ascii")
      .update(wire, "ascii")
      .digest("hex");
    const bip340SignWithSecretThree = (messageHex, publicKey) => {
      const order =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const r = Buffer.from(
        "79be667ef9dcbbac55a06295ce870b070" +
        "29bfcdb2dce28d959f2815b16f81798",
        "hex"
      );
      const tagHash = sha256(Buffer.from("BIP0340/challenge", "utf8"));
      const challenge = bytesToBigEndian(sha256(
        tagHash,
        tagHash,
        r,
        Buffer.from(publicKey, "hex"),
        Buffer.from(messageHex, "hex")
      )) % order;
      return Buffer.concat([
        r,
        bigEndian32((1n + challenge * 3n) % order)
      ]).toString("hex");
    };
    const nativeEd25519 = (message, publicKey, signature) => {
      try {
        return nativeVerify(
          null,
          message,
          createPublicKey({
            key: Buffer.concat([
              Buffer.from("302a300506032b6570032100", "hex"),
              publicKey
            ]),
            format: "der",
            type: "spki"
          }),
          signature
        ) === true;
      } catch {
        return false;
      }
    };

    const seed = Buffer.from(
      "9d61b19deffd5a60ba844af492ec2cc4" +
      "4449c5697b326919703bac031cae7f60",
      "hex"
    );
    const expanded = probeCreateHash("sha512").update(seed).digest();
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    const secretScalar = bytesToLittleEndian(expanded.subarray(0, 32));
    const primePublic = Point.BASE.multiply(secretScalar % CURVE.n).toBytes();
    const orderTwoPoint = Point.fromHex(
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      true
    );
    const mixedPublicPoint = Point.fromHex(primePublic, false)
      .add(orderTwoPoint);
    const mixedPublic = mixedPublicPoint.toBytes();
    const mixedPublicHex = Buffer.from(mixedPublic).toString("hex");
    const sourceApproval = JSON.parse(sourceInput.approvalEvent);
    const sourceAuthorization = JSON.parse(sourceApproval.content);
    const sourcePreEnrollment = JSON.parse(
      sourceAuthorization.preEnrollment
    );
    const sourceEnrollment = JSON.parse(sourceInput.enrollment);
    const sourceContext = JSON.parse(sourceInput.context);
    const subject = sourcePreEnrollment.subject;
    const cryptoOptions = { subject, cryptoImpl: webcrypto };
    const preEnrollmentWire = authorization.createPreEnrollmentV2({
      bindingAuthorizationDigest:
        sourcePreEnrollment.bindingAuthorizationDigest,
      deviceId: sourcePreEnrollment.deviceId,
      ed25519PublicKey: mixedPublicHex,
      expiresAt: sourcePreEnrollment.expiresAt,
      issuedAt: sourcePreEnrollment.issuedAt,
      pairingId: sourcePreEnrollment.pairingId,
      requestId: sourcePreEnrollment.requestId,
      subject,
      x25519BindingId: sourcePreEnrollment.x25519BindingId,
      x25519BindingVersion: sourcePreEnrollment.x25519BindingVersion,
      x25519PublicKeyCommitment:
        sourcePreEnrollment.x25519PublicKeyCommitment
    });
    const authorizationWire = await authorization
      .createAuthorizationEnvelopeV2({
        content: sourceAuthorization.content,
        contextWire: canonical(sourceAuthorization.context),
        preEnrollmentWire
      }, cryptoOptions);
    const approvalEventId = await authorization.approvalEventIdV2(
      authorizationWire,
      cryptoOptions
    );
    const approvalEventWire = await authorization.createApprovalEventV2(
      authorizationWire,
      bip340SignWithSecretThree(approvalEventId, subject),
      cryptoOptions
    );
    const acceptanceId = await authorization.acceptanceIdV2(
      approvalEventWire,
      cryptoOptions
    );
    const enrollmentWire = profile.createEnrollmentV2({
      audience: sourceEnrollment.audience,
      deviceId: sourceEnrollment.deviceId,
      ed25519PublicKey: mixedPublicHex,
      enrollmentChallengeId: sourceEnrollment.enrollmentChallengeId,
      expiresAt: sourceEnrollment.expiresAt,
      issuedAt: sourceEnrollment.issuedAt,
      subject: sourceEnrollment.subject,
      x25519BindingId: sourceEnrollment.x25519BindingId,
      x25519BindingVersion: sourceEnrollment.x25519BindingVersion,
      x25519PublicKeyCommitment:
        sourceEnrollment.x25519PublicKeyCommitment
    });
    const phonePreimage = profile.createEnrollmentProofSigningPreimageV2(
      enrollmentWire
    );
    const message = new TextEncoder().encode(phonePreimage);
    const ed25519Challenge = (r, a) => bytesToLittleEndian(
      probeCreateHash("sha512").update(r).update(a).update(message).digest()
    ) % CURVE.n;
    let nonce;
    let primeR;
    let mixedR;
    let mixedSignature;
    for (let candidate = 1n; candidate < 1_000n; candidate += 1n) {
      const candidatePrimeR = Point.BASE.multiply(candidate).toBytes();
      const candidateMixedR = Point.fromHex(candidatePrimeR, false)
        .add(orderTwoPoint).toBytes();
      const challenge = ed25519Challenge(candidateMixedR, mixedPublic);
      if ((1n + challenge) % 2n !== 0n) continue;
      nonce = candidate;
      primeR = candidatePrimeR;
      mixedR = candidateMixedR;
      mixedSignature = concatenate(
        mixedR,
        littleEndian32(
          (nonce + challenge * secretScalar) % CURVE.n
        )
      );
      break;
    }
    if (mixedSignature === undefined) throw new Error("no torsion solution");
    const primeSignature = concatenate(
      primeR,
      littleEndian32(
        (nonce + ed25519Challenge(primeR, primePublic) * secretScalar) %
          CURVE.n
      )
    );
    const mixedSignatureHex = Buffer.from(mixedSignature).toString("hex");
    const enrollmentDigest = profile.digestEnrollmentV2(enrollmentWire);
    const phoneProofWire = profile.createEnrollmentProofV2({
      enrollmentChallengeId: sourceEnrollment.enrollmentChallengeId,
      enrollmentDigest,
      publicKey: mixedPublicHex,
      signature: mixedSignatureHex
    });
    const associationCreationPreimage = canonical({
      associationVersion: 1,
      deviceId: sourceEnrollment.deviceId,
      ed25519PublicKey: mixedPublicHex,
      enrollmentDigest,
      predecessorAssociationId: null,
      schema:
        "hodlxxi.social_messaging_device_ed25519_association_creation.v1",
      subject,
      version: 1
    });
    const associationId = domainSha256Hex(
      "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1",
      associationCreationPreimage
    );
    const contextWire = canonical({
      ...sourceContext,
      associationId,
      ed25519PublicKey: mixedPublicHex
    });
    const inputWire = canonical({
      acceptanceId,
      approvalEvent: approvalEventWire,
      context: contextWire,
      enrollment: enrollmentWire,
      phoneProof: phoneProofWire,
      schema: sourceInput.schema,
      version: sourceInput.version
    });

    let baselineBrandAccepted = false;
    try {
      await preaccepted.verifyMessagingDevicePreacceptedEnrollmentV2(
        inputWire
      );
      baselineBrandAccepted = true;
    } catch {}
    const baselineProducer = await produce(inputWire, contextWire);
    const uint8ArrayPrototype = Uint8Array.prototype;
    const typedArrayPrototype = Object.getPrototypeOf(uint8ArrayPrototype);
    const ownIteratorDescriptor = Object.getOwnPropertyDescriptor(
      uint8ArrayPrototype,
      Symbol.iterator
    );
    const inheritedIteratorDescriptor = Object.getOwnPropertyDescriptor(
      typedArrayPrototype,
      Symbol.iterator
    );
    let publicMutations = 0;
    let rMutations = 0;
    let signatureSubstitutions = 0;
    let brandAcceptedUnderShadow = false;
    let producerUnderShadow;
    try {
      Object.defineProperty(uint8ArrayPrototype, Symbol.iterator, {
        configurable: true,
        enumerable: false,
        writable: true,
        value() {
          if (equal(this, mixedPublic)) {
            for (let index = 0; index < 32; index += 1) {
              this[index] = primePublic[index];
            }
            publicMutations += 1;
          } else if (equal(this, mixedR)) {
            for (let index = 0; index < 32; index += 1) {
              this[index] = primeR[index];
            }
            rMutations += 1;
          } else if (equal(this, mixedSignature)) {
            signatureSubstitutions += 1;
            return originalApply(
              inheritedIteratorDescriptor.value,
              primeSignature,
              []
            );
          }
          return originalApply(
            inheritedIteratorDescriptor.value,
            this,
            []
          );
        }
      });
      try {
        await preaccepted.verifyMessagingDevicePreacceptedEnrollmentV2(
          inputWire
        );
        brandAcceptedUnderShadow = true;
      } catch {}
      producerUnderShadow = await produce(inputWire, contextWire);
    } finally {
      if (ownIteratorDescriptor === undefined) {
        delete uint8ArrayPrototype[Symbol.iterator];
      } else {
        Object.defineProperty(
          uint8ArrayPrototype,
          Symbol.iterator,
          ownIteratorDescriptor
        );
      }
    }
    const authenticAfterRestore = await produce(
      vector.preacceptedEnrollmentVerificationInputWire,
      vector.verificationContextWire
    );
    return {
      authenticAfterRestore,
      baselineBrandAccepted,
      baselineProducer,
      brandAcceptedUnderShadow,
      inheritedIteratorDescriptorUnchanged:
        Object.getOwnPropertyDescriptor(
          typedArrayPrototype,
          Symbol.iterator
        ).value === inheritedIteratorDescriptor.value,
      mixedNativeAccepted: nativeEd25519(
        message,
        mixedPublic,
        mixedSignature
      ),
      mixedNobleAccepted: nobleVerify(
        mixedSignature,
        message,
        mixedPublic,
        { zip215: false }
      ),
      mixedPublicTorsionFree: mixedPublicPoint.isTorsionFree(),
      ownIteratorOriginallyAbsent: ownIteratorDescriptor === undefined,
      producerUnderShadow,
      publicMutations,
      rMutations,
      signatureSubstitutions
    };
  }

  if (mode === "authentic") {
    return produce(
      vector.preacceptedEnrollmentVerificationInputWire,
      vector.verificationContextWire
    );
  }
  throw new Error(`unknown same-proof probe: ${mode}`);
}

if (process.env[sameProofProbeEnvironment] !== undefined) {
  try {
    const result = await executeSameProofFreshProbe(
      process.env[sameProofProbeEnvironment]
    );
    process.stdout.write(JSON.stringify(result));
    process.exit(0);
  } catch (error) {
    process.stderr.write(String(error?.stack ?? error));
    process.exit(1);
  }
}

function runSameProofFreshProbe(mode) {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(import.meta.url)],
    {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      encoding: "utf8",
      env: { ...process.env, [sameProofProbeEnvironment]: mode },
      maxBuffer: 16 * 1024 * 1024,
      timeout: 60_000
    }
  );
  assert.equal(result.error, undefined, result.error?.stack);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

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

test("fresh process: mixed-torsion own iterator cannot mint a brand or reach the producer signer", () => {
  assert.deepEqual(runSameProofFreshProbe("mixed-torsion-producer"), {
    authenticAfterRestore: {
      accepted: true,
      signerCalls: 1,
      statementExact: true
    },
    baselineBrandAccepted: false,
    baselineProducer: {
      accepted: false,
      signerCalls: 0
    },
    brandAcceptedUnderShadow: false,
    inheritedIteratorDescriptorUnchanged: true,
    mixedNativeAccepted: true,
    mixedNobleAccepted: true,
    mixedPublicTorsionFree: false,
    ownIteratorOriginallyAbsent: true,
    producerUnderShadow: {
      accepted: false,
      signerCalls: 0
    },
    publicMutations: 0,
    rMutations: 0,
    signatureSubstitutions: 0
  });
});

test("fresh process: persistent Gpows plus own iterator cannot confirm alternate bytes", () => {
  assert.deepEqual(runSameProofFreshProbe("combined-gpows-own-iterator"), {
    alternateProducer: {
      accepted: false,
      signerCalls: 0
    },
    baselineAlternateAccepted: false,
    cacheSubstitutions: 1,
    iteratorHookObserved: false,
    ownIteratorOriginallyAbsent: true,
    primedValueEqualsTarget: true,
    primitiveAcceptedWithAlternateBytes: false,
    producerWithAlternateBytes: {
      accepted: false,
      signerCalls: 0
    },
    pushCalls: 4_224,
    rawAlternateAccepted: true,
    signatureSubstitutions: 0
  });
  assert.deepEqual(runSameProofFreshProbe("authentic"), {
    accepted: true,
    signerCalls: 1,
    statementExact: true
  });
});

test("post-import WeakSet.has poisoning cannot forge the result brand", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const forged = Object.freeze({
    authority: "not-granted",
    kind: "caller-forged"
  });
  const descriptor = Object.getOwnPropertyDescriptor(WeakSet.prototype, "has");
  let poisonCalls = 0;
  let projectionError;
  try {
    Object.defineProperty(WeakSet.prototype, "has", {
      ...descriptor,
      value() {
        poisonCalls += 1;
        return true;
      }
    });
    try {
      server.projectMessagingDevicePreacceptedEnrollmentV2(forged);
    } catch (error) {
      projectionError = error;
    }
  } finally {
    Object.defineProperty(WeakSet.prototype, "has", descriptor);
  }
  assert.equal(poisonCalls, 0);
  assert.deepEqual({
    name: projectionError?.name,
    message: projectionError?.message
  }, unavailable);
  assert.throws(
    () => server.projectMessagingDevicePreacceptedEnrollmentV2(forged),
    unavailable
  );
});

test("post-import WeakSet.add poisoning cannot intercept or extend the registry", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const forged = Object.freeze({
    authority: "not-granted",
    kind: "caller-forged"
  });
  const descriptor = Object.getOwnPropertyDescriptor(WeakSet.prototype, "add");
  let interceptedRegistry;
  let poisonCalls = 0;
  let result;
  let verificationError;
  try {
    Object.defineProperty(WeakSet.prototype, "add", {
      ...descriptor,
      value() {
        poisonCalls += 1;
        interceptedRegistry = this;
        return Reflect.apply(descriptor.value, this, [forged]);
      }
    });
    try {
      result = await server.verifyMessagingDevicePreacceptedEnrollmentV2(
        vector.preacceptedEnrollmentVerificationInputWire
      );
    } catch (error) {
      verificationError = error;
    }
  } finally {
    Object.defineProperty(WeakSet.prototype, "add", descriptor);
  }
  assert.equal(verificationError, undefined);
  assert.equal(poisonCalls, 0);
  assert.equal(interceptedRegistry, undefined);
  assert.throws(
    () => server.projectMessagingDevicePreacceptedEnrollmentV2(forged),
    unavailable
  );
  assert.equal(
    server.projectMessagingDevicePreacceptedEnrollmentV2(result).acceptanceId,
    vector.acceptanceId
  );
});

test("post-import Object freeze predicates cannot forge or break the brand", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const result = await server.verifyMessagingDevicePreacceptedEnrollmentV2(
    vector.preacceptedEnrollmentVerificationInputWire
  );
  const forged = Object.freeze({
    authority: "not-granted",
    kind: "caller-forged"
  });
  const freezeDescriptor = Object.getOwnPropertyDescriptor(Object, "freeze");
  const isFrozenDescriptor = Object.getOwnPropertyDescriptor(Object, "isFrozen");
  let freezeReplaced = false;
  let isFrozenReplaced = false;
  let freezePoisonCalls = 0;
  let isFrozenPoisonCalls = 0;
  let forgedError;
  let projection;
  try {
    Object.defineProperty(Object, "freeze", {
      ...freezeDescriptor,
      value() {
        freezePoisonCalls += 1;
        throw new Error("Object.freeze poison entered");
      }
    });
    freezeReplaced = true;
    Object.defineProperty(Object, "isFrozen", {
      ...isFrozenDescriptor,
      value() {
        isFrozenPoisonCalls += 1;
        throw new Error("Object.isFrozen poison entered");
      }
    });
    isFrozenReplaced = true;
    try {
      server.projectMessagingDevicePreacceptedEnrollmentV2(forged);
    } catch (error) {
      forgedError = error;
    }
    projection = server.projectMessagingDevicePreacceptedEnrollmentV2(result);
  } finally {
    if (isFrozenReplaced) {
      Object.defineProperty(Object, "isFrozen", isFrozenDescriptor);
    }
    if (freezeReplaced) {
      Object.defineProperty(Object, "freeze", freezeDescriptor);
    }
  }
  assert.equal(freezePoisonCalls, 0);
  assert.equal(isFrozenPoisonCalls, 0);
  assert.deepEqual({
    name: forgedError?.name,
    message: forgedError?.message
  }, unavailable);
  assert.equal(projection.acceptanceId, vector.acceptanceId);
  assert.equal(
    server.projectMessagingDevicePreacceptedEnrollmentV2(result).acceptanceId,
    vector.acceptanceId
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

test("builtin bindings and SHA-256 Hash methods are captured before exports", async () => {
  const source = await readFile(new URL(
    "../src/server/messaging-device-preaccepted-enrollment-v2.mjs",
    import.meta.url
  ), "utf8");
  const capture = "const safeIsProxy = isProxy;";
  assert.equal(source.indexOf("const safeBuffer = Buffer;") < source.indexOf("export "), true);
  assert.equal(source.indexOf("const safeCreateHash = createHash;") < source.indexOf("export "), true);
  assert.equal(source.indexOf(capture) < source.indexOf("export "), true);
  for (const primordialCapture of [
    "const safeObjectFreeze = Object.freeze;",
    "const safeObjectIsFrozen = Object.isFrozen;",
    "const safeWeakSetAdd = WeakSet.prototype.add;",
    "const safeWeakSetHas = WeakSet.prototype.has;"
  ]) {
    assert.equal(source.indexOf(primordialCapture) < source.indexOf("export "), true);
  }
  assert.match(source, /const safeApply = Reflect\.apply;/);
  assert.match(source,
    /const sha256HashPrototype = Object\.getPrototypeOf\(safeCreateHash\("sha256"\)\);/);
  assert.match(source, /const safeSha256HashUpdate = sha256HashPrototype\.update;/);
  assert.match(source, /const safeSha256HashDigest = sha256HashPrototype\.digest;/);
  assert.match(source, /const safeBufferByteLength = safeBuffer\.byteLength;/);
  const afterCaptures = source.slice(source.indexOf(capture) + capture.length);
  assert.doesNotMatch(afterCaptures, /\b(?:Buffer|createHash|isProxy)\b/);
  assert.doesNotMatch(afterCaptures, /\.(?:update|digest)\s*\(/);
  assert.match(source,
    /safeApply\(safeBufferByteLength, safeBuffer, \[source, "utf8"\]\)/);
  assert.match(source, /safeApply\(safeSha256HashUpdate, hash,/);
  assert.match(source, /safeApply\(safeSha256HashDigest, hash,/);
  assert.match(source, /function digestArrayBuffer\(bytes\)/);
  assert.match(source, /new SafeArrayBuffer\(length\)/);
  assert.doesNotMatch(source, /bytes\.buffer|\.buffer\.slice/);
  assert.match(source, /descriptor\(safeGlobalThis, "Boolean"\)/);
  assert.match(source, /descriptor\(SafeJSON, "parse"\)/);
  assert.match(source,
    /descriptor\(SafeTextEncoder\.prototype, "encode"\)/);
  assert.match(source, /function strictVerifyBip340Exact\(/);
  assert.match(source,
    /return point !== null && !\(point\.y & 1n\) && point\.x === r;/);
  assert.match(source,
    /safeApply\(safeWeakSetAdd, verifiedResults, \[result\]\);/);
  assert.match(source,
    /safeApply\(safeWeakSetHas, verifiedResults, \[result\]\)/);
  const afterPrimordialCaptures = source.slice(
    source.indexOf("const safeWeakSetHas = WeakSet.prototype.has;") +
      "const safeWeakSetHas = WeakSet.prototype.has;".length
  );
  assert.doesNotMatch(afterPrimordialCaptures,
    /\bObject\.(?:freeze|isFrozen)\s*\(/);
  assert.doesNotMatch(afterPrimordialCaptures,
    /verifiedResults\.(?:add|has)\s*\(/);
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
