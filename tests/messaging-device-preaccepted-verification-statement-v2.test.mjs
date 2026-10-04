import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  verify as cryptoVerify
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Same-process mutation cases below are non-exhaustive, non-normative
// defense-in-depth regressions for the exact hooks exercised. Arbitrary code
// mutating the trusted Node process is process compromise, not a supported
// security boundary or a condition these tests add to commit readiness.

const freshProbeEnvironment =
  "HODLXXI_SOCIAL_NATIVE_ED25519_BACKSTOP_FRESH_PROBE";

async function executeFreshProbe(mode) {
  const statement = JSON.parse(await readFile(new URL(
    "./fixtures/social_preaccepted_enrollment_verification_statement_v2.json",
    import.meta.url
  )));
  const source = JSON.parse(await readFile(new URL(
    "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
    import.meta.url
  )));
  const server = await import(
    "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs"
  );
  const fixtureVector = statement.vector;
  const sourceFixtureVector = source.vector;
  const fixtureConfiguration = statement.configuration;
  const fixtureDeadlines = statement.deadlines;
  const fixtureInput = JSON.parse(
    sourceFixtureVector.preacceptedEnrollmentVerificationInputWire
  );
  const fixturePhoneProof = JSON.parse(fixtureInput.phoneProof);
  const probeEnabled = Object.freeze({
    preacceptedEnrollmentVerificationStatementsV2Enabled: true
  });
  const sortRecursively = (value) => {
    if (Array.isArray(value)) return value.map(sortRecursively);
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(Object.keys(value).sort().map(
        (key) => [key, sortRecursively(value[key])]
      ));
    }
    return value;
  };
  const canonicalize = (value) => JSON.stringify(sortRecursively(value));
  const wireWithSignature = (signature) => canonicalize({
    ...fixtureInput,
    phoneProof: canonicalize({ ...fixturePhoneProof, signature })
  });
  const createSigner = (signExact) => server
    .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2({
      algorithm:
        server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
      audience: fixtureConfiguration.audience,
      clientId: fixtureConfiguration.clientId,
      issuer: fixtureConfiguration.issuer,
      kid: fixtureConfiguration.kid,
      purpose:
        server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
      servicePrincipal: fixtureConfiguration.servicePrincipal,
      signExact
    });
  const createProducerInput = (signingPort, inputWire) => ({
    approverSessionExpiresAtMs: fixtureDeadlines.approverSessionExpiresAtMs,
    contextWire: sourceFixtureVector.verificationContextWire,
    expectedAlgorithm:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
    expectedAudience: fixtureConfiguration.audience,
    expectedClientId: fixtureConfiguration.clientId,
    expectedIssuer: fixtureConfiguration.issuer,
    expectedKid: fixtureConfiguration.kid,
    expectedPurpose:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
    expectedServicePrincipal: fixtureConfiguration.servicePrincipal,
    fullExpiresAtMs: fixtureDeadlines.fullExpiresAtMs,
    inputWire,
    now: fixtureDeadlines.now,
    phoneSessionExpiresAtMs: fixtureDeadlines.phoneSessionExpiresAtMs,
    signer: signingPort,
    statementLifetimeMs: 9_000,
    x25519BindingExpiresAtMs: fixtureDeadlines.x25519BindingExpiresAtMs
  });
  const produce = async (inputWire, signExact) => {
    let calls = 0;
    const signingPort = createSigner((bytes) => {
      calls += 1;
      return signExact(bytes);
    });
    try {
      const value = await server
        .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
          createProducerInput(signingPort, inputWire),
          probeEnabled
        );
      return { accepted: true, calls, value };
    } catch {
      return { accepted: false, calls };
    }
  };
  const rejectingSigner = () => {
    throw new Error("invalid Ed25519 evidence reached signExact");
  };
  const authenticR = fixturePhoneProof.signature.slice(0, 64);
  const callerInvalidScalar = "01" + "00".repeat(31);
  const callerInvalidSignature = authenticR + callerInvalidScalar;
  const callerInvalidInput = wireWithSignature(callerInvalidSignature);

  if (mode === "typed-array-iterator") {
    const { strictVerifyMessagingDeviceEd25519V1 } = await import(
      "../src/server/messaging-device-proof-profile-v1.mjs"
    );
    const message = new TextEncoder().encode(
      sourceFixtureVector.enrollmentPhoneProofSigningPreimage
    );
    const authenticBytes = new Uint8Array(
      Buffer.from(fixturePhoneProof.signature, "hex")
    );
    const invalidBytes = new Uint8Array(
      Buffer.from(callerInvalidSignature, "hex")
    );
    const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(
      typedArrayPrototype,
      Symbol.iterator
    );
    const originalApply = Reflect.apply;
    let hookCalls = 0;
    let substitutions = 0;
    let invalidOutcome;
    let invalidPrimitiveAccepted;
    let authenticPrimitiveAccepted;
    let invalidVerificationHookCalls;
    let authenticVerificationHookCalls;
    try {
      Object.defineProperty(typedArrayPrototype, Symbol.iterator, {
        ...iteratorDescriptor,
        value() {
          hookCalls += 1;
          let targeted = this instanceof Uint8Array &&
            this.length === invalidBytes.length;
          for (let index = 0; targeted && index < invalidBytes.length; index += 1) {
            if (this[index] !== invalidBytes[index]) targeted = false;
          }
          if (targeted) substitutions += 1;
          return originalApply(
            iteratorDescriptor.value,
            targeted ? authenticBytes : this,
            []
          );
        }
      });
      const beforeInvalid = hookCalls;
      invalidPrimitiveAccepted = strictVerifyMessagingDeviceEd25519V1(
        message,
        fixturePhoneProof.publicKey,
        callerInvalidSignature
      );
      invalidVerificationHookCalls = hookCalls - beforeInvalid;
      const beforeAuthentic = hookCalls;
      authenticPrimitiveAccepted = strictVerifyMessagingDeviceEd25519V1(
        message,
        fixturePhoneProof.publicKey,
        fixturePhoneProof.signature
      );
      authenticVerificationHookCalls = hookCalls - beforeAuthentic;
      invalidOutcome = await produce(callerInvalidInput, rejectingSigner);
    } finally {
      Object.defineProperty(
        typedArrayPrototype,
        Symbol.iterator,
        iteratorDescriptor
      );
    }
    return {
      authenticAcceptedWhilePoisoned: authenticPrimitiveAccepted,
      authenticVerificationHookCalls,
      forgedAccepted: invalidOutcome.accepted,
      forgedSignerCalls: invalidOutcome.calls,
      hookCalls: invalidVerificationHookCalls,
      nativeRejectedInvalidBytes: invalidPrimitiveAccepted === false,
      substitutions
    };
  }

  if (mode === "poisoned-gpows") {
    const {
      CURVE,
      Point,
      verify: nobleVerify
    } = await import("@noble/ed25519");
    const message = new TextEncoder().encode(
      sourceFixtureVector.enrollmentPhoneProofSigningPreimage
    );
    const publicPoint = Point.fromHex(fixturePhoneProof.publicKey, false);
    const signaturePoint = Point.fromHex(authenticR, false);
    const challengeHash = createHash("sha512")
      .update(Buffer.from(authenticR, "hex"))
      .update(Buffer.from(fixturePhoneProof.publicKey, "hex"))
      .update(message)
      .digest();
    let challenge = 0n;
    for (let index = challengeHash.length - 1; index >= 0; index -= 1) {
      challenge = (challenge << 8n) | BigInt(challengeHash[index]);
    }
    challenge %= CURVE.n;
    const target = signaturePoint.add(publicPoint.multiply(challenge, false));
    const pushDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      "push"
    );
    const originalApply = Reflect.apply;
    let pushCalls = 0;
    let substitutions = 0;
    let primed;
    try {
      Object.defineProperty(Array.prototype, "push", {
        ...pushDescriptor,
        value(...items) {
          pushCalls += 1;
          if (pushCalls === 2 && items.length === 1) {
            substitutions += 1;
            return originalApply(pushDescriptor.value, this, [target]);
          }
          return originalApply(pushDescriptor.value, this, items);
        }
      });
      primed = Point.BASE.multiply(2n, false);
    } finally {
      Object.defineProperty(Array.prototype, "push", pushDescriptor);
    }
    const forgedSignature = authenticR + "02" + "00".repeat(31);
    const nobleAccepted = nobleVerify(
      new Uint8Array(Buffer.from(forgedSignature, "hex")),
      message,
      new Uint8Array(Buffer.from(fixturePhoneProof.publicKey, "hex")),
      { zip215: false }
    );
    const outcome = await produce(
      wireWithSignature(forgedSignature),
      rejectingSigner
    );
    return {
      forgedAccepted: outcome.accepted,
      nobleAccepted,
      primedValueEqualsTarget: primed.equals(target),
      pushCalls,
      signerCalls: outcome.calls,
      substitutions
    };
  }

  if (mode === "native-boundary") {
    const { createRequire, syncBuiltinESMExports } = await import("node:module");
    const { strictVerifyMessagingDeviceEd25519V1 } = await import(
      "../src/server/messaging-device-proof-profile-v1.mjs"
    );
    const require = createRequire(import.meta.url);
    const crypto = require("node:crypto");
    const createPublicKeyDescriptor = Object.getOwnPropertyDescriptor(
      crypto,
      "createPublicKey"
    );
    const verifyDescriptor = Object.getOwnPropertyDescriptor(crypto, "verify");
    const authenticStatementSignature = Buffer.from(
      fixtureVector.signature,
      "base64url"
    );
    const originalApply = Reflect.apply;
    let createPublicKeyReplacementCalls = 0;
    let verifyReplacementCalls = 0;
    let bufferConversionCalls = 0;
    let bufferIteratorCalls = 0;
    let typedArrayConversionCalls = 0;
    let typedArrayIteratorCalls = 0;
    let authenticOutcome;
    let forgedOutcome;
    let invalidPrimitiveAccepted;
    const mutationDescriptors = [];
    const restore = (target, key, descriptor) => {
      if (descriptor === undefined) delete target[key];
      else Object.defineProperty(target, key, descriptor);
    };
    try {
      Object.defineProperty(crypto, "createPublicKey", {
        ...createPublicKeyDescriptor,
        value() {
          createPublicKeyReplacementCalls += 1;
          throw new Error("replacement createPublicKey entered");
        }
      });
      Object.defineProperty(crypto, "verify", {
        ...verifyDescriptor,
        value() {
          verifyReplacementCalls += 1;
          return true;
        }
      });
      syncBuiltinESMExports();
      authenticOutcome = await produce(
        sourceFixtureVector.preacceptedEnrollmentVerificationInputWire,
        () => authenticStatementSignature
      );

      const typedArrayConstructor = Object.getPrototypeOf(Uint8Array);
      const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
      const mutations = [
        [Buffer, "from", () => { bufferConversionCalls += 1; }],
        [Buffer.prototype, Symbol.iterator, () => { bufferIteratorCalls += 1; }],
        [typedArrayConstructor, "from", () => {
          typedArrayConversionCalls += 1;
        }],
        [typedArrayPrototype, Symbol.iterator, () => {
          typedArrayIteratorCalls += 1;
        }]
      ];
      for (const [target, key, entered] of mutations) {
        const descriptor = Object.getOwnPropertyDescriptor(target, key);
        const inherited = target[key];
        mutationDescriptors.push([target, key, descriptor]);
        Object.defineProperty(target, key, {
          configurable: descriptor?.configurable ?? true,
          enumerable: descriptor?.enumerable ?? false,
          writable: descriptor?.writable ?? true,
          value(...args) {
            entered();
            return originalApply(descriptor?.value ?? inherited, this, args);
          }
        });
      }
      invalidPrimitiveAccepted = strictVerifyMessagingDeviceEd25519V1(
        new TextEncoder().encode(
          sourceFixtureVector.enrollmentPhoneProofSigningPreimage
        ),
        fixturePhoneProof.publicKey,
        callerInvalidSignature
      );
      for (let index = mutationDescriptors.length - 1; index >= 0; index -= 1) {
        restore(...mutationDescriptors[index]);
      }
      mutationDescriptors.length = 0;
      forgedOutcome = await produce(callerInvalidInput, rejectingSigner);
    } finally {
      for (let index = mutationDescriptors.length - 1; index >= 0; index -= 1) {
        restore(...mutationDescriptors[index]);
      }
      Object.defineProperty(crypto, "verify", verifyDescriptor);
      Object.defineProperty(
        crypto,
        "createPublicKey",
        createPublicKeyDescriptor
      );
      syncBuiltinESMExports();
    }
    return {
      authenticAccepted: authenticOutcome.accepted,
      authenticSignerCalls: authenticOutcome.calls,
      authenticStatementExact: authenticOutcome.value === fixtureVector.compactJws,
      bufferConversionCalls,
      bufferIteratorCalls,
      createPublicKeyReplacementCalls,
      forgedAccepted: forgedOutcome.accepted,
      forgedSignerCalls: forgedOutcome.calls,
      nativeRejectedInvalidBytes: invalidPrimitiveAccepted === false,
      typedArrayConversionCalls,
      typedArrayIteratorCalls,
      verifyReplacementCalls
    };
  }

  if (mode === "normal") {
    const expectedSignature = Buffer.from(fixtureVector.signature, "base64url");
    const signingInputs = [];
    const outcome = await produce(
      sourceFixtureVector.preacceptedEnrollmentVerificationInputWire,
      (bytes) => {
        signingInputs.push(bytes.toString("ascii"));
        return expectedSignature;
      }
    );
    return {
      accepted: outcome.accepted,
      signerCalls: outcome.calls,
      signingInputExact:
        signingInputs.length === 1 &&
        signingInputs[0] === fixtureVector.signingInput,
      statementExact: outcome.value === fixtureVector.compactJws
    };
  }

  throw new Error(`unknown fresh probe: ${mode}`);
}

if (process.env[freshProbeEnvironment] !== undefined) {
  try {
    const result = await executeFreshProbe(process.env[freshProbeEnvironment]);
    process.stdout.write(JSON.stringify(result));
    process.exit(0);
  } catch (error) {
    process.stderr.write(String(error?.stack ?? error));
    process.exit(1);
  }
}

const statementFixtureBytes = await readFile(new URL(
  "./fixtures/social_preaccepted_enrollment_verification_statement_v2.json",
  import.meta.url
));
const sourceFixtureBytes = await readFile(new URL(
  "./fixtures/social_preacceptance_ed25519_handoff_v2.json",
  import.meta.url
));
const statementFixture = JSON.parse(statementFixtureBytes);
const sourceFixture = JSON.parse(sourceFixtureBytes);
const vector = statementFixture.vector;
const sourceVector = sourceFixture.vector;
const configuration = statementFixture.configuration;
const deadlines = statementFixture.deadlines;
const enabled = Object.freeze({
  preacceptedEnrollmentVerificationStatementsV2Enabled: true
});
const unavailable = {
  name: "TypeError",
  message:
    "messaging device preaccepted enrollment verification statement v2 unavailable"
};
const verifierUnavailable = {
  name: "TypeError",
  message: "messaging device preaccepted enrollment v2 unavailable"
};
const v1Unavailable = {
  name: "TypeError",
  message: "messaging device verification statement unavailable"
};

function recursivelySorted(value) {
  if (Array.isArray(value)) return value.map(recursivelySorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map(
        (key) => [key, recursivelySorted(value[key])]
      )
    );
  }
  return value;
}

const canonical = (value) => JSON.stringify(recursivelySorted(value));
const change = (wire, changes) => canonical({ ...JSON.parse(wire), ...changes });
const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");
const domainSha256Hex = (domain, value) => createHash("sha256")
  .update(domain + "\0", "ascii")
  .update(value, "ascii")
  .digest("hex");
const auditFieldP =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const auditCurveN =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const auditGenerator = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
const auditMod = (value, modulus = auditFieldP) => {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
};
function auditPow(base, exponent) {
  let result = 1n;
  let factor = auditMod(base);
  for (let value = exponent; value > 0n; value >>= 1n) {
    if (value & 1n) result = auditMod(result * factor);
    factor = auditMod(factor * factor);
  }
  return result;
}
function auditPointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x) {
    if (auditMod(left.y + right.y) === 0n) return null;
    const slope = auditMod(
      3n * left.x * left.x * auditPow(2n * left.y, auditFieldP - 2n)
    );
    const x = auditMod(slope * slope - 2n * left.x);
    return { x, y: auditMod(slope * (left.x - x) - left.y) };
  }
  const slope = auditMod(
    (right.y - left.y) * auditPow(right.x - left.x, auditFieldP - 2n)
  );
  const x = auditMod(slope * slope - left.x - right.x);
  return { x, y: auditMod(slope * (left.x - x) - left.y) };
}
function auditPointMultiply(scalar, point = auditGenerator) {
  let result = null;
  let addend = point;
  for (let value = scalar; value > 0n; value >>= 1n) {
    if (value & 1n) result = auditPointAdd(result, addend);
    addend = auditPointAdd(addend, addend);
  }
  return result;
}
const auditBytes32 = (value) => Buffer.from(
  value.toString(16).padStart(64, "0"),
  "hex"
);
function auditTaggedHash(tag, value) {
  const tagHash = createHash("sha256").update(tag, "ascii").digest();
  return createHash("sha256")
    .update(tagHash)
    .update(tagHash)
    .update(value)
    .digest();
}
function auditBip340Sign(messageHex) {
  const privateScalar = 3n;
  const publicPoint = auditPointMultiply(privateScalar);
  const adjustedPrivate = publicPoint.y & 1n
    ? auditCurveN - privateScalar
    : privateScalar;
  const nonce = 1n;
  const noncePoint = auditPointMultiply(nonce);
  const challenge = BigInt(`0x${auditTaggedHash(
    "BIP0340/challenge",
    Buffer.concat([
      auditBytes32(noncePoint.x),
      auditBytes32(publicPoint.x),
      Buffer.from(messageHex, "hex")
    ])
  ).toString("hex")}`) % auditCurveN;
  const scalar = auditMod(
    nonce + challenge * adjustedPrivate,
    auditCurveN
  );
  return auditBytes32(noncePoint.x).toString("hex") +
    auditBytes32(scalar).toString("hex");
}

function signedAuditInput({ lifecycle = {}, preEnrollment = {} } = {}) {
  const input = JSON.parse(sourceVector.preacceptedEnrollmentVerificationInputWire);
  const event = JSON.parse(input.approvalEvent);
  const authorization = JSON.parse(event.content);
  const claimContainer = JSON.parse(authorization.content);
  Object.assign(claimContainer.authorization, lifecycle);
  authorization.content = canonical(claimContainer);
  const pre = JSON.parse(authorization.preEnrollment);
  Object.assign(pre, preEnrollment);
  if (!Object.hasOwn(preEnrollment, "bindingAuthorizationDigest")) {
    pre.bindingAuthorizationDigest = sha256Hex(authorization.content);
  }
  authorization.preEnrollment = canonical(pre);
  event.content = canonical(authorization);
  const preEnrollmentDigest =
    "hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:" +
    domainSha256Hex(
      "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_DIGEST_V2",
      authorization.preEnrollment
    );
  event.tags = [
    ["purpose", "hodlxxi-social-messaging-device-qr-pre-enrollment-approval-v2"],
    ["authorization-digest", sha256Hex(event.content)],
    ["pre-enrollment-digest", preEnrollmentDigest],
    ["request-id", pre.requestId],
    ["action", "register"],
    ["pairing-id", pre.pairingId]
  ];
  event.id = sha256Hex(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]));
  event.sig = auditBip340Sign(event.id);
  input.approvalEvent = canonical(event);
  const acceptanceIdPreimage = canonical({
    approvalEventId: event.id,
    authorizationDigest: sha256Hex(event.content),
    bindingId: pre.x25519BindingId,
    pairingId: pre.pairingId,
    preEnrollmentDigest,
    requestId: pre.requestId,
    schema: "hodlxxi.social_mobile_pre_enrollment_acceptance_id_preimage.v2",
    subject: pre.subject,
    version: 2
  });
  input.acceptanceId = domainSha256Hex(
    "HODLXXI_SOCIAL_MOBILE_PRE_ENROLLMENT_ACCEPTANCE_ID_V2",
    acceptanceIdPreimage
  );
  return canonical(input);
}
const inputWith = (changes) => change(
  sourceVector.preacceptedEnrollmentVerificationInputWire,
  changes
);
const bip340GeneratorX =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ed25519Basepoint =
  "5866666666666666666666666666666666666666666666666666666666666666";
const sourceInput = JSON.parse(
  sourceVector.preacceptedEnrollmentVerificationInputWire
);
const sourceApprovalEvent = JSON.parse(sourceInput.approvalEvent);
const sourcePhoneProof = JSON.parse(sourceInput.phoneProof);
const forgedBip340InputWire = canonical({
  ...sourceInput,
  approvalEvent: canonical({
    ...sourceApprovalEvent,
    sig: bip340GeneratorX + "0".repeat(63) + "1"
  })
});
const forgedEd25519InputWire = canonical({
  ...sourceInput,
  phoneProof: canonical({
    ...sourcePhoneProof,
    signature: ed25519Basepoint + "01" + "00".repeat(31)
  })
});
const sourceEnrollment = JSON.parse(sourceInput.enrollment);
const sourceContext = JSON.parse(sourceInput.context);
const alteredEnrollment = {
  ...sourceEnrollment,
  expiresAt: sourceEnrollment.expiresAt - 1_000
};
const alteredEnrollmentWire = canonical(alteredEnrollment);
const alteredEnrollmentDigest =
  "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
  createHash("sha256")
    .update(
      "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2\0",
      "ascii"
    )
    .update(alteredEnrollmentWire, "ascii")
    .digest("hex");
const alteredAssociationCreationPreimage = canonical({
  associationVersion: 1,
  deviceId: alteredEnrollment.deviceId,
  ed25519PublicKey: alteredEnrollment.ed25519PublicKey,
  enrollmentDigest: alteredEnrollmentDigest,
  predecessorAssociationId: null,
  schema: "hodlxxi.social_messaging_device_ed25519_association_creation.v1",
  subject: alteredEnrollment.subject,
  version: 1
});
const alteredAssociationId = createHash("sha256")
  .update(
    "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1\0",
    "ascii"
  )
  .update(alteredAssociationCreationPreimage, "ascii")
  .digest("hex");
const alteredContextWire = canonical({
  ...sourceContext,
  associationId: alteredAssociationId
});
const alteredPhoneProofWire = canonical({
  ...sourcePhoneProof,
  enrollmentDigest: alteredEnrollmentDigest
});
const encoderReplayInputWire = canonical({
  ...sourceInput,
  context: alteredContextWire,
  enrollment: alteredEnrollmentWire,
  phoneProof: alteredPhoneProofWire
});
const alteredPhonePreimage = canonical({
  domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2",
  enrollment: alteredEnrollmentWire,
  profile: "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1",
  publicKey: sourcePhoneProof.publicKey,
  schema: "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2",
  version: 2
});
const bip340TagHash = createHash("sha256")
  .update(new TextEncoder().encode("BIP0340/challenge"))
  .digest();
const bip340ChallengePreimage = Buffer.concat([
  bip340TagHash,
  bip340TagHash,
  Buffer.from(bip340GeneratorX, "hex"),
  Buffer.from(sourceApprovalEvent.pubkey, "hex"),
  Buffer.from(sourceApprovalEvent.id, "hex")
]);
const bip340ChallengeDigest = createHash("sha256")
  .update(bip340ChallengePreimage)
  .digest();
const ed25519ChallengePreimage = Buffer.concat([
  Buffer.from(ed25519Basepoint, "hex"),
  Buffer.from(sourcePhoneProof.publicKey, "hex"),
  Buffer.from(sourceVector.enrollmentPhoneProofSigningPreimage, "utf8")
]);
const ed25519ChallengeDigest = createHash("sha512")
  .update(ed25519ChallengePreimage)
  .digest();

async function loadServer(t) {
  try {
    return await import(
      "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs"
    );
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

function signer(server, signExact, overrides = {}) {
  return server
    .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2({
      algorithm:
        server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
      audience: configuration.audience,
      clientId: configuration.clientId,
      issuer: configuration.issuer,
      kid: configuration.kid,
      purpose:
        server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
      servicePrincipal: configuration.servicePrincipal,
      signExact,
      ...overrides
    });
}

function producerInput(server, signingPort, changes = {}) {
  return {
    approverSessionExpiresAtMs: deadlines.approverSessionExpiresAtMs,
    contextWire: sourceVector.verificationContextWire,
    expectedAlgorithm:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_ALGORITHM,
    expectedAudience: configuration.audience,
    expectedClientId: configuration.clientId,
    expectedIssuer: configuration.issuer,
    expectedKid: configuration.kid,
    expectedPurpose:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
    expectedServicePrincipal: configuration.servicePrincipal,
    fullExpiresAtMs: deadlines.fullExpiresAtMs,
    inputWire: sourceVector.preacceptedEnrollmentVerificationInputWire,
    now: deadlines.now,
    phoneSessionExpiresAtMs: deadlines.phoneSessionExpiresAtMs,
    signer: signingPort,
    statementLifetimeMs: 9_000,
    x25519BindingExpiresAtMs: deadlines.x25519BindingExpiresAtMs,
    ...changes
  };
}

async function forgedProducerOutcome(server, inputWire, changes = {}) {
  let calls = 0;
  const signingPort = signer(server, () => {
    calls += 1;
    return Buffer.alloc(256);
  });
  try {
    await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, { inputWire, ...changes }),
        enabled
      );
    return { accepted: true, calls };
  } catch {
    return { accepted: false, calls };
  }
}

async function primitiveProducerOutcome(server, inputWire, changes = {}) {
  let calls = 0;
  const signingPort = signer(server, () => {
    calls += 1;
    return Buffer.alloc(256);
  });
  try {
    await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, { inputWire, ...changes }),
        enabled
      );
    return `accepted:${calls}`;
  } catch {
    return `denied:${calls}`;
  }
}

const denied = (call) => assert.throws(call, unavailable);
const deniedAsync = (call) => assert.rejects(call, unavailable);

function runFreshProbe(mode) {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(import.meta.url)],
    {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      encoding: "utf8",
      env: { ...process.env, [freshProbeEnvironment]: mode },
      maxBuffer: 16 * 1024 * 1024,
      timeout: 60_000
    }
  );
  assert.equal(result.error, undefined, result.error?.stack);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

test("both exact public fixtures are pinned byte-for-byte", () => {
  assert.equal(statementFixtureBytes.byteLength, 12_018);
  assert.equal(
    createHash("sha256").update(statementFixtureBytes).digest("hex"),
    "fdbbed748f28d1ef850ef3d82b1680e7dca12b0f7a2d863acf14dc7b75770f39"
  );
  assert.equal(sourceFixtureBytes.byteLength, 32_998);
  assert.equal(
    createHash("sha256").update(sourceFixtureBytes).digest("hex"),
    "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc"
  );
  assert.equal(statementFixture.sourceFixture.bytes, sourceFixtureBytes.byteLength);
  assert.equal(statementFixture.sourceFixture.sha256,
    createHash("sha256").update(sourceFixtureBytes).digest("hex"));
  assert.equal(statementFixture.sourceFixture.verificationInputDigest,
    sourceVector.preacceptedEnrollmentVerificationInputDigest);
});

test("the real verifier reproduces the exact UBID compact JWS", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, (signingInput) => {
    calls += 1;
    assert.equal(signingInput.toString("ascii"), vector.signingInput);
    return Buffer.from(vector.signature, "base64url");
  });
  const statement = await server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort),
      enabled
    );
  assert.equal(calls, 1);
  assert.equal(statement, vector.compactJws);
  const segments = statement.split(".");
  assert.equal(segments.length, 3);
  assert.equal(segments.every((segment) => segment.length > 0), true);
  assert.equal(segments.some((segment) => segment.includes("=")), false);
  assert.equal(Buffer.from(segments[0], "base64url").toString("ascii"),
    vector.protectedHeaderWire);
  assert.equal(Buffer.from(segments[1], "base64url").toString("ascii"),
    vector.payloadWire);
  assert.deepEqual(JSON.parse(vector.protectedHeaderWire), {
    alg: "RS256",
    kid: configuration.kid,
    typ: "hodlxxi-social-preaccepted-enrollment-verification-v2+jws"
  });
  assert.deepEqual(Object.keys(JSON.parse(vector.payloadWire)).sort(), [
    "acceptanceId", "associationId", "attemptId", "aud", "clientId",
    "enrollmentChallengeId", "expiresAt", "inputDigest", "iss", "issuedAt",
    "jti", "purpose", "result", "schema", "servicePrincipal", "version"
  ]);
});

test("array-iterator next cannot substitute an enrollment digest or reach signExact", async (t) => {
  const server = await loadServer(t);
  if (server === null) return;
  const input = JSON.parse(sourceVector.preacceptedEnrollmentVerificationInputWire);
  const enrollment = JSON.parse(input.enrollment);
  const phoneProof = JSON.parse(input.phoneProof);
  const context = JSON.parse(input.context);
  const replacementHashSource = "attacker-selected-non-enrollment";
  const forgedEnrollmentDigest =
    "hodlxxi-social-messaging-device-enrollment-v2-sha256:" +
    domainSha256Hex(
      "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2",
      replacementHashSource
    );
  phoneProof.enrollmentDigest = forgedEnrollmentDigest;
  const associationPreimage = canonical({
    associationVersion: 1,
    deviceId: enrollment.deviceId,
    ed25519PublicKey: enrollment.ed25519PublicKey,
    enrollmentDigest: forgedEnrollmentDigest,
    predecessorAssociationId: null,
    schema: "hodlxxi.social_messaging_device_ed25519_association_creation.v1",
    subject: enrollment.subject,
    version: 1
  });
  context.associationId = domainSha256Hex(
    "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1",
    associationPreimage
  );
  input.phoneProof = canonical(phoneProof);
  input.context = canonical(context);
  const invalidWire = canonical(input);
  assert.deepEqual(
    await forgedProducerOutcome(server, invalidWire, {
      contextWire: input.context
    }),
    { accepted: false, calls: 0 }
  );

  const iteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]());
  const descriptor = Object.getOwnPropertyDescriptor(iteratorPrototype, "next");
  const originalApply = Reflect.apply;
  try {
    Object.defineProperty(iteratorPrototype, "next", {
      ...descriptor,
      value() {
        const step = originalApply(descriptor.value, this, []);
        if (
          step.done === false && step.value === input.enrollment &&
          (new Error().stack ?? "").includes(
            "messaging-device-proof-profile-v1.mjs"
          )
        ) step.value = replacementHashSource;
        return step;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, invalidWire, {
        contextWire: input.context
      }),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(iteratorPrototype, "next", descriptor);
  }
});

test("array-iterator next cannot repair a signed invalid lifecycle record", async (t) => {
  const server = await loadServer(t);
  if (server === null) return;
  const invalidSchema = "invalid.binding.record.schema";
  const validSchema = "hodlxxi.social_messaging_device_binding_record.v1";
  const invalidWire = signedAuditInput({
    lifecycle: { bindingRecordSchema: invalidSchema }
  });
  assert.deepEqual(
    await forgedProducerOutcome(server, invalidWire),
    { accepted: false, calls: 0 }
  );
  const iteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]());
  const descriptor = Object.getOwnPropertyDescriptor(iteratorPrototype, "next");
  const originalApply = Reflect.apply;
  try {
    Object.defineProperty(iteratorPrototype, "next", {
      ...descriptor,
      value() {
        const step = originalApply(descriptor.value, this, []);
        if (
          step.done === false && Array.isArray(step.value) &&
          step.value.length === 2 &&
          step.value[0] === "bindingRecordSchema" &&
          step.value[1] === invalidSchema &&
          (new Error().stack ?? "").includes(
            "messaging-device-authorization-v1.mjs"
          )
        ) step.value[1] = validSchema;
        return step;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, invalidWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(iteratorPrototype, "next", descriptor);
  }
});

test("inherited toJSON cannot detach the binding ID from its signed record", async (t) => {
  const server = await loadServer(t);
  if (server === null) return;
  const input = JSON.parse(sourceVector.preacceptedEnrollmentVerificationInputWire);
  const event = JSON.parse(input.approvalEvent);
  const authorization = JSON.parse(event.content);
  const claim = JSON.parse(authorization.content).authorization;
  const originalExpiry = claim.bindingExpiresAt;
  const alteredExpiry = "2026-10-09T22:29:59Z";
  const invalidWire = signedAuditInput({
    lifecycle: { bindingExpiresAt: alteredExpiry }
  });
  const changes = { x25519BindingExpiresAtMs: Date.parse(alteredExpiry) };
  assert.deepEqual(
    await forgedProducerOutcome(server, invalidWire, changes),
    { accepted: false, calls: 0 }
  );
  const objectDescriptor = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "toJSON"
  );
  try {
    Object.defineProperty(Object.prototype, "toJSON", {
      configurable: true,
      enumerable: false,
      writable: true,
      value() {
        if (
          this !== null && typeof this === "object" &&
          this.expiresAt === alteredExpiry &&
          this.validFrom === claim.bindingValidFrom &&
          this.schema === "hodlxxi.social_messaging_device_binding_record.v1"
        ) return { ...this, expiresAt: originalExpiry };
        return this;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, invalidWire, changes),
      { accepted: false, calls: 0 }
    );
  } finally {
    if (objectDescriptor === undefined) delete Object.prototype.toJSON;
    else Object.defineProperty(Object.prototype, "toJSON", objectDescriptor);
  }

  const arrayDescriptor = Object.getOwnPropertyDescriptor(
    Array.prototype,
    "toJSON"
  );
  try {
    Object.defineProperty(Array.prototype, "toJSON", {
      configurable: true,
      enumerable: false,
      writable: true,
      value() { return this; }
    });
    assert.deepEqual(
      await forgedProducerOutcome(
        server,
        sourceVector.preacceptedEnrollmentVerificationInputWire
      ),
      { accepted: false, calls: 0 }
    );
  } finally {
    if (arrayDescriptor === undefined) delete Array.prototype.toJSON;
    else Object.defineProperty(Array.prototype, "toJSON", arrayDescriptor);
  }
});

test("transient inherited then hooks cannot replace trusted digest results", async (t) => {
  const server = await loadServer(t);
  if (server === null) return;
  const invalidWire = signedAuditInput({
    preEnrollment: { bindingAuthorizationDigest: "00".repeat(32) }
  });
  assert.equal(
    await primitiveProducerOutcome(server, invalidWire),
    "denied:0"
  );
  const input = JSON.parse(invalidWire);
  const event = JSON.parse(input.approvalEvent);
  const authorization = JSON.parse(event.content);
  const targetDigest = createHash("sha256")
    .update(authorization.content, "utf8")
    .digest();
  const objectDescriptor = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "then"
  );
  const inheritedThen = function inheritedThen(resolve) {
    let selected = this;
    if (this instanceof ArrayBuffer && this.byteLength === 32) {
      const bytes = new Uint8Array(this);
      let targeted = true;
      for (let index = 0; index < 32; index += 1) {
        if (bytes[index] !== targetDigest[index]) targeted = false;
      }
      if (targeted) selected = new ArrayBuffer(32);
    }
    delete Object.prototype.then;
    try {
      resolve(selected);
    } finally {
      Object.defineProperty(Object.prototype, "then", {
        configurable: true,
        enumerable: false,
        writable: true,
        value: inheritedThen
      });
    }
  };
  try {
    Object.defineProperty(Object.prototype, "then", {
      configurable: true,
      enumerable: false,
      writable: true,
      value: inheritedThen
    });
    assert.equal(
      await primitiveProducerOutcome(server, invalidWire),
      "denied:0"
    );
  } finally {
    if (objectDescriptor === undefined) delete Object.prototype.then;
    else Object.defineProperty(Object.prototype, "then", objectDescriptor);
  }

  const arrayBufferDescriptor = Object.getOwnPropertyDescriptor(
    ArrayBuffer.prototype,
    "then"
  );
  try {
    Object.defineProperty(ArrayBuffer.prototype, "then", {
      configurable: true,
      enumerable: false,
      writable: true,
      value(resolve) { resolve(this); }
    });
    assert.equal(
      await primitiveProducerOutcome(
        server,
        sourceVector.preacceptedEnrollmentVerificationInputWire
      ),
      "denied:0"
    );
  } finally {
    if (arrayBufferDescriptor === undefined) {
      delete ArrayBuffer.prototype.then;
    } else {
      Object.defineProperty(
        ArrayBuffer.prototype,
        "then",
        arrayBufferDescriptor
      );
    }
  }
});

test("fresh process: typed-array iterator substitution denies before Noble", () => {
  assert.deepEqual(runFreshProbe("typed-array-iterator"), {
    authenticAcceptedWhilePoisoned: false,
    authenticVerificationHookCalls: 0,
    forgedAccepted: false,
    forgedSignerCalls: 0,
    hookCalls: 0,
    nativeRejectedInvalidBytes: true,
    substitutions: 0
  });
});

test("fresh process: poisoned Noble Gpows cannot bypass the native gate", () => {
  assert.deepEqual(runFreshProbe("poisoned-gpows"), {
    forgedAccepted: false,
    nobleAccepted: true,
    primedValueEqualsTarget: true,
    pushCalls: 4_224,
    signerCalls: 0,
    substitutions: 1
  });
});

test("fresh process: native bindings and direct-copy inputs resist poisoning", () => {
  assert.deepEqual(runFreshProbe("native-boundary"), {
    authenticAccepted: true,
    authenticSignerCalls: 1,
    authenticStatementExact: true,
    bufferConversionCalls: 0,
    bufferIteratorCalls: 0,
    createPublicKeyReplacementCalls: 0,
    forgedAccepted: false,
    forgedSignerCalls: 0,
    nativeRejectedInvalidBytes: true,
    typedArrayConversionCalls: 0,
    typedArrayIteratorCalls: 0,
    verifyReplacementCalls: 0
  });
});

test("fresh process: authentic input requires both verifiers and signs once", () => {
  assert.deepEqual(runFreshProbe("normal"), {
    accepted: true,
    signerCalls: 1,
    signingInputExact: true,
    statementExact: true
  });
});

test("inherited TypedArray.from substitution cannot mint evidence or reach signExact", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedEd25519InputWire),
    { accepted: false, calls: 0 }
  );

  const forgedSignature = ed25519Basepoint + "01" + "00".repeat(31);
  const forgedPairs = [];
  for (let index = 0; index < 64; index += 1) {
    forgedPairs.push(forgedSignature.slice(index * 2, index * 2 + 2));
  }
  const authenticSignatureBytes = new Uint8Array(
    Buffer.from(sourcePhoneProof.signature, "hex")
  );
  const typedArrayConstructor = Object.getPrototypeOf(Uint8Array);
  const descriptor = Object.getOwnPropertyDescriptor(
    typedArrayConstructor,
    "from"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(typedArrayConstructor, "from", {
      ...descriptor,
      value(...args) {
        poisonCalls += 1;
        const source = args[0];
        let exactForgedPairs = Array.isArray(source) && source.length === 64;
        for (let index = 0; exactForgedPairs && index < 64; index += 1) {
          if (source[index] !== forgedPairs[index]) exactForgedPairs = false;
        }
        if (this === Uint8Array && exactForgedPairs) {
          return authenticSignatureBytes;
        }
        return originalApply(descriptor.value, this, args);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(typedArrayConstructor, "from", descriptor);
  }
  assert.equal(poisonCalls, 0);

  let signerCalls = 0;
  const signingPort = signer(server, (signingInput) => {
    signerCalls += 1;
    assert.equal(signingInput.toString("ascii"), vector.signingInput);
    return Buffer.from(vector.signature, "base64url");
  });
  const statement = await server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort),
      enabled
    );
  assert.equal(signerCalls, 1);
  assert.equal(statement, vector.compactJws);
});

test("the reproduced statement independently verifies under the public fixture JWK", () => {
  const publicKey = createPublicKey({
    key: statementFixture.publicVerificationMaterial.jwk,
    format: "jwk"
  });
  assert.equal(cryptoVerify(
    "RSA-SHA256",
    Buffer.from(vector.signingInput, "ascii"),
    publicKey,
    Buffer.from(vector.signature, "base64url")
  ), true);
  assert.equal(
    createHash("sha256")
      .update(
        "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2\0",
        "ascii"
      )
      .update(vector.payloadWithoutJtiWire, "ascii")
      .digest("hex"),
    vector.jti
  );
});

test("the signer port is immutable, opaque and purpose-bound", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const signingPort = signer(server, () => Buffer.alloc(256));
  assert.deepEqual(Object.keys(signingPort).sort(), [
    "algorithm", "audience", "clientId", "issuer", "kid", "purpose",
    "servicePrincipal"
  ]);
  assert.equal(Object.values(signingPort).some(
    (value) => typeof value === "function"
  ), false);
  assert.equal(Object.isFrozen(signingPort), true);
});

test("record-validation primordial poisons cannot discover signExact", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const targets = [
    [Array, "isArray"],
    [Object, "create"],
    [Object, "freeze"],
    [Object, "getOwnPropertyDescriptors"],
    [Object, "getPrototypeOf"],
    [Object, "hasOwn"],
    [Reflect, "ownKeys"],
    [RegExp.prototype, "exec"],
    [String.prototype, "slice"]
  ];
  const descriptors = targets.map(([target, key]) => [
    target,
    key,
    Object.getOwnPropertyDescriptor(target, key)
  ]);
  const originalApply = Reflect.apply;
  const originalHasOwn = Object.hasOwn;
  const signExact = () => Buffer.alloc(256);
  const signerInput = {
    algorithm: "RS256",
    audience: configuration.audience,
    clientId: configuration.clientId,
    issuer: configuration.issuer,
    kid: configuration.kid,
    purpose:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
    servicePrincipal: configuration.servicePrincipal,
    signExact
  };
  let disclosed;
  let targetedPoisonCalls = 0;
  let signingPort;
  try {
    for (const [target, key, descriptor] of descriptors) {
      Object.defineProperty(target, key, {
        ...descriptor,
        value(...args) {
          const candidate = args[0];
          const targetsSignerInput = candidate === signerInput;
          const targetsSignerDescriptors =
            candidate !== null && typeof candidate === "object" &&
            originalHasOwn(candidate, "signExact");
          const targetsSignerText =
            candidate === configuration.audience ||
            candidate === configuration.issuer ||
            candidate === configuration.kid ||
            this === configuration.audience || this === configuration.issuer ||
            this === configuration.kid;
          if (
            targetsSignerInput || targetsSignerDescriptors ||
            targetsSignerText || (key === "create" && candidate === null)
          ) {
            targetedPoisonCalls += 1;
            disclosed = targetsSignerInput
              ? signerInput.signExact
              : candidate?.signExact?.value;
            throw new Error(`poisoned ${key} reached`);
          }
          return originalApply(descriptor.value, this, args);
        }
      });
    }
    signingPort = server
      .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2(
        signerInput
      );
  } finally {
    for (let index = descriptors.length - 1; index >= 0; index -= 1) {
      const [target, key, descriptor] = descriptors[index];
      Object.defineProperty(target, key, descriptor);
    }
  }
  assert.equal(targetedPoisonCalls, 0);
  assert.equal(disclosed, undefined);
  assert.equal(Object.isFrozen(signingPort), true);
  assert.equal(Object.values(signingPort).includes(signExact), false);
});

test("post-import isProxy synchronization cannot disclose signExact", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const utilTypes = require("node:util/types");
  const originalIsProxy = utilTypes.isProxy;
  let replacementCalls = 0;
  let signerCalls = 0;
  let disclosed;
  let signingPort;
  const signExact = () => {
    signerCalls += 1;
    return Buffer.alloc(256);
  };
  try {
    utilTypes.isProxy = (candidate) => {
      replacementCalls += 1;
      if (
        candidate === signExact ||
        (candidate !== null && typeof candidate === "object" &&
          candidate.signExact === signExact)
      ) disclosed = signExact;
      return originalIsProxy(candidate);
    };
    syncBuiltinESMExports();
    signingPort = signer(server, signExact);
  } finally {
    utilTypes.isProxy = originalIsProxy;
    syncBuiltinESMExports();
  }
  assert.equal(replacementCalls, 0);
  assert.equal(disclosed, undefined);
  assert.equal(signerCalls, 0);
  assert.equal(Object.isFrozen(signingPort), true);
  assert.equal(Object.values(signingPort).includes(signExact), false);
});

test("post-import createHash synchronization cannot pre-seed producer hashes", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const crypto = require("node:crypto");
  const originalCreateHash = crypto.createHash;
  const originalFrom = Buffer.from;
  const originalToString = Buffer.prototype.toString;
  const originalApply = Reflect.apply;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let replacementCalls = 0;
  let targetedPoisonCalls = 0;
  let signerCalls = 0;
  let statement;
  const signingPort = signer(server, (bytes) => {
    signerCalls += 1;
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });
  try {
    crypto.createHash = (...args) => {
      replacementCalls += 1;
      const hash = originalCreateHash(...args);
      if ((new Error().stack ?? "").includes("at tokenId ")) {
        targetedPoisonCalls += 1;
        return hash.update("ATTACKER-PRESEED", "ascii");
      }
      return hash;
    };
    syncBuiltinESMExports();
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    crypto.createHash = originalCreateHash;
    syncBuiltinESMExports();
  }
  assert.equal(replacementCalls, 0);
  assert.equal(targetedPoisonCalls, 0);
  assert.equal(signerCalls, 1);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("forged BIP340 stays denied after createHash export synchronization", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedBip340InputWire),
    { accepted: false, calls: 0 }
  );
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const crypto = require("node:crypto");
  const createHashDescriptor = Object.getOwnPropertyDescriptor(
    crypto,
    "createHash"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(crypto, "createHash", {
      ...createHashDescriptor,
      value(algorithm, options) {
        const hash = originalApply(
          createHashDescriptor.value,
          crypto,
          [algorithm, options]
        );
        return {
          update(source, encoding) {
            if (
              algorithm === "sha256" && source instanceof Uint8Array &&
              source.byteLength === 160
            ) {
              poisonCalls += 1;
              return { digest: () => Buffer.alloc(32) };
            }
            originalApply(
              Object.getPrototypeOf(hash).update,
              hash,
              [source, encoding]
            );
            return this;
          },
          digest(encoding) {
            return originalApply(
              Object.getPrototypeOf(hash).digest,
              hash,
              [encoding]
            );
          }
        };
      }
    });
    syncBuiltinESMExports();
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(crypto, "createHash", createHashDescriptor);
    syncBuiltinESMExports();
  }
  assert.equal(poisonCalls, 0);
});

test("forged Ed25519 stays denied after createHash export synchronization", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedEd25519InputWire),
    { accepted: false, calls: 0 }
  );
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const crypto = require("node:crypto");
  const createHashDescriptor = Object.getOwnPropertyDescriptor(
    crypto,
    "createHash"
  );
  let poisonCalls = 0;
  try {
    Object.defineProperty(crypto, "createHash", {
      ...createHashDescriptor,
      value(algorithm, options) {
        if (algorithm === "sha512") {
          return {
            update() { return this; },
            digest() {
              poisonCalls += 1;
              return Buffer.alloc(64);
            }
          };
        }
        return createHashDescriptor.value(algorithm, options);
      }
    });
    syncBuiltinESMExports();
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(crypto, "createHash", createHashDescriptor);
    syncBuiltinESMExports();
  }
  assert.equal(poisonCalls, 0);
});

test("upstream isProxy and Buffer export replacements never enter verification", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const utilTypes = require("node:util/types");
  const bufferBuiltin = require("node:buffer");
  const isProxyDescriptor = Object.getOwnPropertyDescriptor(utilTypes, "isProxy");
  const bufferDescriptor = Object.getOwnPropertyDescriptor(
    bufferBuiltin,
    "Buffer"
  );
  const originalBuffer = bufferDescriptor.value;
  const originalApply = Reflect.apply;
  const originalByteLength = originalBuffer.byteLength;
  let isProxyCalls = 0;
  let bufferByteLengthCalls = 0;
  let signerCalls = 0;
  const signingPort = signer(server, () => {
    signerCalls += 1;
    return Buffer.alloc(256);
  });
  const replacementBuffer = new Proxy(originalBuffer, {
    get(target, property) {
      if (property === "byteLength") {
        return (...args) => {
          bufferByteLengthCalls += 1;
          return originalApply(originalByteLength, originalBuffer, args);
        };
      }
      return Reflect.get(target, property, target);
    }
  });
  const replacementIsProxy = (value) => {
    isProxyCalls += 1;
    return originalApply(isProxyDescriptor.value, utilTypes, [value]);
  };
  try {
    Object.defineProperty(utilTypes, "isProxy", {
      ...isProxyDescriptor,
      value: replacementIsProxy
    });
    Object.defineProperty(bufferBuiltin, "Buffer", {
      ...bufferDescriptor,
      value: replacementBuffer
    });
    syncBuiltinESMExports();
    assert.equal(
      (await import("node:util/types")).isProxy,
      replacementIsProxy
    );
    assert.equal((await import("node:buffer")).Buffer, replacementBuffer);
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, {
          inputWire: inputWith({ version: 1 })
        }),
        enabled
      ));
  } finally {
    Object.defineProperty(bufferBuiltin, "Buffer", bufferDescriptor);
    Object.defineProperty(utilTypes, "isProxy", isProxyDescriptor);
    syncBuiltinESMExports();
  }
  assert.equal(isProxyCalls, 0);
  assert.equal(bufferByteLengthCalls, 0);
  assert.equal(signerCalls, 0);
});

test("post-import Buffer synchronization preserves exact signing bytes", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const require = createRequire(import.meta.url);
  const bufferBuiltin = require("node:buffer");
  const originalBuffer = bufferBuiltin.Buffer;
  const originalApply = Reflect.apply;
  const originalFrom = originalBuffer.from;
  const originalToString = originalBuffer.prototype.toString;
  const signature = originalApply(
    originalFrom,
    originalBuffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let replacementReads = 0;
  let producerReads = 0;
  let signerCalls = 0;
  let statement;
  const signingPort = signer(server, (bytes) => {
    signerCalls += 1;
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });
  const replacementBuffer = new Proxy(originalBuffer, {
    get(target, property) {
      replacementReads += 1;
      const stack = new Error().stack ?? "";
      if (
        !stack.includes("messaging-device-preaccepted-enrollment-v2.mjs") &&
        /at (?:closedVerifiedJson|base64urlAscii|exactSignatureBytes|Module\.produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2) /.test(
          stack
        )
      ) {
        producerReads += 1;
        if (property === "from") {
          return () => originalApply(originalFrom, originalBuffer, [
            "ATTACKER-CONTROLLED-BYTES",
            "ascii"
          ]);
        }
        if (property === "byteLength") return () => Number.MAX_SAFE_INTEGER;
      }
      return Reflect.get(target, property, target);
    }
  });
  try {
    bufferBuiltin.Buffer = replacementBuffer;
    syncBuiltinESMExports();
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    bufferBuiltin.Buffer = originalBuffer;
    syncBuiltinESMExports();
  }
  assert.equal(replacementReads > 0, true);
  assert.equal(producerReads, 0);
  assert.equal(signerCalls, 1);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("poisoned Reflect.apply cannot create a chosen-message signing oracle", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const applyDescriptor = Object.getOwnPropertyDescriptor(Reflect, "apply");
  const originalApply = applyDescriptor.value;
  const originalFrom = Buffer.from;
  const originalToString = Buffer.prototype.toString;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let targetedPoisonCalls = 0;
  const signExact = (bytes) => {
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  };
  const signingPort = signer(server, signExact);
  let statement;
  try {
    Object.defineProperty(Reflect, "apply", {
      ...applyDescriptor,
      value(target, thisArgument, argumentsList) {
        if (target === signExact) {
          targetedPoisonCalls += 1;
          originalApply(target, thisArgument, [
            originalApply(originalFrom, Buffer, [
              "ATTACKER-CONTROLLED-BYTES",
              "ascii"
            ])
          ]);
        }
        return originalApply(target, thisArgument, argumentsList);
      }
    });
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    Object.defineProperty(Reflect, "apply", applyDescriptor);
  }
  assert.equal(targetedPoisonCalls, 0);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("poisoned WeakMap.prototype.set cannot intercept opaque signer state", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const setDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "set");
  const originalApply = Reflect.apply;
  const originalFrom = Buffer.from;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  let poisonCalls = 0;
  let calls = 0;
  let signingPort;
  try {
    Object.defineProperty(WeakMap.prototype, "set", {
      ...setDescriptor,
      value() {
        poisonCalls += 1;
        throw new Error("poisoned WeakMap set reached");
      }
    });
    signingPort = signer(server, () => {
      calls += 1;
      return signature;
    });
  } finally {
    Object.defineProperty(WeakMap.prototype, "set", setDescriptor);
  }
  const statement = await server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort),
      enabled
    );
  assert.equal(poisonCalls, 0);
  assert.equal(calls, 1);
  assert.equal(statement, vector.compactJws);
});

test("poisoned WeakMap has/get cannot disclose, forge or alter signer state", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const hasDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "has");
  const getDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "get");
  const originalApply = Reflect.apply;
  const originalFrom = Buffer.from;
  const originalToString = Buffer.prototype.toString;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let forgedCalls = 0;
  let targetedHasCalls = 0;
  let targetedGetCalls = 0;
  let disclosed;
  const registered = signer(server, (bytes) => {
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });
  const unregistered = Object.freeze({ ...registered });
  const forgedState = Object.freeze({
    ...registered,
    signExact() {
      forgedCalls += 1;
      return signature;
    }
  });
  let statement;
  try {
    Object.defineProperty(WeakMap.prototype, "has", {
      ...hasDescriptor,
      value(key) {
        if (key === registered || key === unregistered) {
          targetedHasCalls += 1;
          return true;
        }
        return originalApply(hasDescriptor.value, this, [key]);
      }
    });
    Object.defineProperty(WeakMap.prototype, "get", {
      ...getDescriptor,
      value(key) {
        if (key === registered || key === unregistered) {
          targetedGetCalls += 1;
          disclosed = originalApply(getDescriptor.value, this, [key]);
          return forgedState;
        }
        return originalApply(getDescriptor.value, this, [key]);
      }
    });
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, unregistered),
        enabled
      ));
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, registered),
        enabled
      );
  } finally {
    Object.defineProperty(WeakMap.prototype, "get", getDescriptor);
    Object.defineProperty(WeakMap.prototype, "has", hasDescriptor);
  }
  assert.equal(targetedHasCalls, 0);
  assert.equal(targetedGetCalls, 0);
  assert.equal(disclosed, undefined);
  assert.equal(forgedCalls, 0);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("poisoned Buffer.from cannot replace the exact signer input", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const fromDescriptor = Object.getOwnPropertyDescriptor(Buffer, "from");
  const originalApply = Reflect.apply;
  const originalToString = Buffer.prototype.toString;
  const signature = originalApply(
    fromDescriptor.value,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let targetedPoisonCalls = 0;
  const signingPort = signer(server, (bytes) => {
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });
  let statement;
  try {
    Object.defineProperty(Buffer, "from", {
      ...fromDescriptor,
      value(value, encoding) {
        if (value === vector.signingInput && encoding === "ascii") {
          targetedPoisonCalls += 1;
          return originalApply(fromDescriptor.value, Buffer, [
            "ATTACKER-CONTROLLED-BYTES",
            "ascii"
          ]);
        }
        return originalApply(fromDescriptor.value, Buffer, arguments);
      }
    });
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    Object.defineProperty(Buffer, "from", fromDescriptor);
  }
  assert.equal(targetedPoisonCalls, 0);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("poisoned Buffer toString cannot alter any compact JWS segment", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const toStringDescriptor = Object.getOwnPropertyDescriptor(
    Buffer.prototype,
    "toString"
  );
  const originalApply = Reflect.apply;
  const originalFrom = Buffer.from;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let targetedPoisonCalls = 0;
  const signingPort = signer(server, (bytes) => {
    seen.push(originalApply(toStringDescriptor.value, bytes, ["ascii"]));
    return signature;
  });
  let statement;
  try {
    Object.defineProperty(Buffer.prototype, "toString", {
      ...toStringDescriptor,
      value(encoding, ...rest) {
        if (encoding === "base64url") {
          targetedPoisonCalls += 1;
          return "ATTACKER-CONTROLLED-SEGMENT";
        }
        return originalApply(toStringDescriptor.value, this, [encoding, ...rest]);
      }
    });
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    Object.defineProperty(Buffer.prototype, "toString", toStringDescriptor);
  }
  assert.equal(targetedPoisonCalls, 0);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("JSON poisons installed across a verifier await fail closed", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const parseDescriptor = Object.getOwnPropertyDescriptor(JSON, "parse");
  const stringifyDescriptor = Object.getOwnPropertyDescriptor(JSON, "stringify");
  const originalApply = Reflect.apply;
  const expectedAttemptId = originalApply(
    parseDescriptor.value,
    JSON,
    [sourceVector.verificationContextWire]
  ).attemptId;
  const originalFrom = Buffer.from;
  const originalToString = Buffer.prototype.toString;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const seen = [];
  let parsePoisonCalls = 0;
  let stringifyPoisonCalls = 0;
  const signingPort = signer(server, (bytes) => {
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });

  // The async producer and verifier have synchronously consumed their initial
  // exact input before returning this Promise. Poisoning here spans every
  // subsequent verifier await and the complete local signing-record build.
  const pending = server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort),
      enabled
    );
  let verificationError;
  try {
    Object.defineProperty(JSON, "parse", {
      ...parseDescriptor,
      value(source, ...rest) {
        const parsed = originalApply(parseDescriptor.value, JSON, [source, ...rest]);
        if (source === sourceVector.verificationContextWire) {
          parsePoisonCalls += 1;
          parsed.attemptId = "00".repeat(32);
          parsed.subject = "01".repeat(32);
        }
        return parsed;
      }
    });
    Object.defineProperty(JSON, "stringify", {
      ...stringifyDescriptor,
      value(value, ...rest) {
        if (
          (value !== null && typeof value === "object" &&
            value.schema ===
              server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_SCHEMA) ||
          value === configuration.kid ||
          value ===
            server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE ||
          value === expectedAttemptId
        ) {
          stringifyPoisonCalls += 1;
          return "{\"attacker\":true}";
        }
        return originalApply(stringifyDescriptor.value, JSON, [value, ...rest]);
      }
    });
    try {
      await pending;
    } catch (error) {
      verificationError = error;
    }
  } finally {
    Object.defineProperty(JSON, "stringify", stringifyDescriptor);
    Object.defineProperty(JSON, "parse", parseDescriptor);
  }
  assert.equal(parsePoisonCalls, 0);
  assert.equal(stringifyPoisonCalls, 0);
  assert.deepEqual(seen, []);
  assert.deepEqual({
    name: verificationError?.name,
    message: verificationError?.message
  }, unavailable);
});

test("poisoned SHA-256 update/digest cannot change canonical signing bytes", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const originalApply = Reflect.apply;
  const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
  const updateDescriptor = Object.getOwnPropertyDescriptor(hashPrototype, "update");
  const digestDescriptor = Object.getOwnPropertyDescriptor(hashPrototype, "digest");
  const originalFrom = Buffer.from;
  const originalToString = Buffer.prototype.toString;
  const signature = originalApply(
    originalFrom,
    Buffer,
    [vector.signature, "base64url"]
  );
  const targetedHashes = new WeakSet();
  const seen = [];
  let targetedPoisonCalls = 0;
  const signingPort = signer(server, (bytes) => {
    seen.push(originalApply(originalToString, bytes, ["ascii"]));
    return signature;
  });
  let statement;
  try {
    Object.defineProperty(hashPrototype, "update", {
      ...updateDescriptor,
      value(source, encoding) {
        if (
          source ===
            "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2\0"
        ) {
          targetedPoisonCalls += 1;
          targetedHashes.add(this);
          source = "ATTACKER-CONTROLLED-BYTES";
          encoding = "ascii";
        }
        return originalApply(updateDescriptor.value, this, [source, encoding]);
      }
    });
    Object.defineProperty(hashPrototype, "digest", {
      ...digestDescriptor,
      value(encoding) {
        if (targetedHashes.has(this)) return "00".repeat(32);
        return originalApply(digestDescriptor.value, this, [encoding]);
      }
    });
    statement = await server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      );
  } finally {
    Object.defineProperty(hashPrototype, "digest", digestDescriptor);
    Object.defineProperty(hashPrototype, "update", updateDescriptor);
  }
  assert.equal(targetedPoisonCalls, 0);
  assert.deepEqual(seen, [vector.signingInput]);
  assert.equal(statement, vector.compactJws);
});

test("forged BIP340 stays denied after SHA-256 Hash update poisoning", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedBip340InputWire),
    { accepted: false, calls: 0 }
  );
  const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
  const updateDescriptor = Object.getOwnPropertyDescriptor(
    hashPrototype,
    "update"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(hashPrototype, "update", {
      ...updateDescriptor,
      value(source, encoding) {
        if (
          source instanceof Uint8Array && source.byteLength === 160 &&
          Buffer.from(source).equals(bip340ChallengePreimage)
        ) {
          poisonCalls += 1;
          return { digest: () => Buffer.alloc(32) };
        }
        return originalApply(
          updateDescriptor.value,
          this,
          [source, encoding]
        );
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(hashPrototype, "update", updateDescriptor);
  }
  assert.equal(poisonCalls, 0);
});

test("forged BIP340 stays denied after SHA-256 Hash digest poisoning", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedBip340InputWire),
    { accepted: false, calls: 0 }
  );
  const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
  const digestDescriptor = Object.getOwnPropertyDescriptor(
    hashPrototype,
    "digest"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(hashPrototype, "digest", {
      ...digestDescriptor,
      value(encoding) {
        const result = originalApply(digestDescriptor.value, this, [encoding]);
        if (
          encoding === undefined && result instanceof Uint8Array &&
          result.byteLength === 32 &&
          Buffer.from(result).equals(bip340ChallengeDigest)
        ) {
          poisonCalls += 1;
          return Buffer.alloc(32);
        }
        return result;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(hashPrototype, "digest", digestDescriptor);
  }
  assert.equal(poisonCalls, 0);
});

test("post-import canonical parser substitutions deny before signer dispatch", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedEd25519InputWire),
    { accepted: false, calls: 0 }
  );
  const originalApply = Reflect.apply;
  const parseDescriptor = Object.getOwnPropertyDescriptor(JSON, "parse");
  const stringifyDescriptor = Object.getOwnPropertyDescriptor(JSON, "stringify");
  const descriptorsDescriptor = Object.getOwnPropertyDescriptor(
    Object,
    "getOwnPropertyDescriptors"
  );
  const forgedProofWire = JSON.parse(forgedEd25519InputWire).phoneProof;
  const authenticProofWire = sourceInput.phoneProof;
  let parseSubstitutions = 0;
  let stringifySubstitutions = 0;
  try {
    Object.defineProperty(JSON, "parse", {
      ...parseDescriptor,
      value(source, ...rest) {
        if (source === forgedProofWire) {
          parseSubstitutions += 1;
          return originalApply(
            parseDescriptor.value,
            JSON,
            [authenticProofWire, ...rest]
          );
        }
        return originalApply(parseDescriptor.value, JSON, [source, ...rest]);
      }
    });
    Object.defineProperty(JSON, "stringify", {
      ...stringifyDescriptor,
      value(value, ...rest) {
        if (
          value !== null && typeof value === "object" &&
          value.schema ===
            "hodlxxi.social_messaging_device_enrollment_proof.v2" &&
          value.signature === sourcePhoneProof.signature
        ) {
          stringifySubstitutions += 1;
          return forgedProofWire;
        }
        return originalApply(stringifyDescriptor.value, JSON, [value, ...rest]);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(JSON, "stringify", stringifyDescriptor);
    Object.defineProperty(JSON, "parse", parseDescriptor);
  }
  assert.equal(parseSubstitutions, 0);
  assert.equal(stringifySubstitutions, 0);

  let descriptorSubstitutions = 0;
  try {
    Object.defineProperty(Object, "getOwnPropertyDescriptors", {
      ...descriptorsDescriptor,
      value(target) {
        const descriptors = originalApply(
          descriptorsDescriptor.value,
          Object,
          [target]
        );
        if (
          target !== null && typeof target === "object" &&
          target.schema ===
            "hodlxxi.social_messaging_device_enrollment_proof.v2" &&
          target.signature !== sourcePhoneProof.signature
        ) {
          descriptorSubstitutions += 1;
          descriptors.signature = {
            ...descriptors.signature,
            value: sourcePhoneProof.signature
          };
        }
        return descriptors;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(
      Object,
      "getOwnPropertyDescriptors",
      descriptorsDescriptor
    );
  }
  assert.equal(descriptorSubstitutions, 0);
});

test("post-import TextEncoder replay cannot detach Ed25519 from its wire", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, encoderReplayInputWire, {
      contextWire: alteredContextWire
    }),
    { accepted: false, calls: 0 }
  );
  const encodeDescriptor = Object.getOwnPropertyDescriptor(
    TextEncoder.prototype,
    "encode"
  );
  const originalApply = Reflect.apply;
  const authenticPreimageBytes = originalApply(
    encodeDescriptor.value,
    new TextEncoder(),
    [sourceVector.enrollmentPhoneProofSigningPreimage]
  );
  let substitutions = 0;
  try {
    Object.defineProperty(TextEncoder.prototype, "encode", {
      ...encodeDescriptor,
      value(source) {
        if (source === alteredPhonePreimage) {
          substitutions += 1;
          return authenticPreimageBytes;
        }
        return originalApply(encodeDescriptor.value, this, arguments);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, encoderReplayInputWire, {
        contextWire: alteredContextWire
      }),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(TextEncoder.prototype, "encode", encodeDescriptor);
  }
  assert.equal(substitutions, 0);
});

test("post-import BIP340 conversion and Boolean poisons deny with zero signer calls", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedBip340InputWire),
    { accepted: false, calls: 0 }
  );
  const originalApply = Reflect.apply;
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const inheritedBufferDescriptor = Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    "buffer"
  );
  const ownBufferDescriptor = Object.getOwnPropertyDescriptor(
    Buffer.prototype,
    "buffer"
  );
  let bufferSubstitutions = 0;
  try {
    Object.defineProperty(Buffer.prototype, "buffer", {
      configurable: true,
      enumerable: false,
      get() {
        let targeted = this.length === bip340ChallengeDigest.length;
        for (let index = 0; targeted && index < this.length; index += 1) {
          if (this[index] !== bip340ChallengeDigest[index]) targeted = false;
        }
        if (targeted) {
          bufferSubstitutions += 1;
          return new ArrayBuffer(this.byteOffset + this.byteLength);
        }
        return originalApply(inheritedBufferDescriptor.get, this, []);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    if (ownBufferDescriptor === undefined) delete Buffer.prototype.buffer;
    else Object.defineProperty(Buffer.prototype, "buffer", ownBufferDescriptor);
  }
  assert.equal(bufferSubstitutions, 0);

  const sliceDescriptor = Object.getOwnPropertyDescriptor(
    ArrayBuffer.prototype,
    "slice"
  );
  let sliceSubstitutions = 0;
  try {
    Object.defineProperty(ArrayBuffer.prototype, "slice", {
      ...sliceDescriptor,
      value(start, end) {
        const length = end - start;
        let targeted = length === bip340ChallengeDigest.length;
        const view = targeted ? new Uint8Array(this, start, length) : null;
        for (let index = 0; targeted && index < length; index += 1) {
          if (view[index] !== bip340ChallengeDigest[index]) targeted = false;
        }
        if (targeted) {
          sliceSubstitutions += 1;
          return new ArrayBuffer(length);
        }
        return originalApply(sliceDescriptor.value, this, arguments);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(ArrayBuffer.prototype, "slice", sliceDescriptor);
  }
  assert.equal(sliceSubstitutions, 0);

  const booleanDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "Boolean"
  );
  let booleanSubstitutions = 0;
  try {
    Object.defineProperty(globalThis, "Boolean", {
      ...booleanDescriptor,
      value(value) {
        if (value === false) {
          booleanSubstitutions += 1;
          return true;
        }
        return originalApply(booleanDescriptor.value, undefined, [value]);
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedBip340InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(globalThis, "Boolean", booleanDescriptor);
  }
  assert.equal(booleanSubstitutions, 0);
});

test("forged Ed25519 stays denied after SHA-512 Hash update poisoning", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedEd25519InputWire),
    { accepted: false, calls: 0 }
  );
  const hashPrototype = Object.getPrototypeOf(createHash("sha512"));
  const updateDescriptor = Object.getOwnPropertyDescriptor(
    hashPrototype,
    "update"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(hashPrototype, "update", {
      ...updateDescriptor,
      value(source, encoding) {
        if (
          source instanceof Uint8Array &&
          source.byteLength === ed25519ChallengePreimage.byteLength &&
          Buffer.from(source).equals(ed25519ChallengePreimage)
        ) {
          poisonCalls += 1;
          Object.defineProperty(this, "digest", {
            configurable: true,
            value: () => Buffer.alloc(64),
            writable: true
          });
        }
        return originalApply(
          updateDescriptor.value,
          this,
          [source, encoding]
        );
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(hashPrototype, "update", updateDescriptor);
  }
  assert.equal(poisonCalls, 0);
});

test("forged Ed25519 stays denied after SHA-512 Hash digest poisoning", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.deepEqual(
    await forgedProducerOutcome(server, forgedEd25519InputWire),
    { accepted: false, calls: 0 }
  );
  const hashPrototype = Object.getPrototypeOf(createHash("sha512"));
  const digestDescriptor = Object.getOwnPropertyDescriptor(
    hashPrototype,
    "digest"
  );
  const originalApply = Reflect.apply;
  let poisonCalls = 0;
  try {
    Object.defineProperty(hashPrototype, "digest", {
      ...digestDescriptor,
      value(encoding) {
        const result = originalApply(digestDescriptor.value, this, [encoding]);
        if (
          encoding === undefined && result instanceof Uint8Array &&
          result.byteLength === 64 &&
          Buffer.from(result).equals(ed25519ChallengeDigest)
        ) {
          poisonCalls += 1;
          return Buffer.alloc(64);
        }
        return result;
      }
    });
    assert.deepEqual(
      await forgedProducerOutcome(server, forgedEd25519InputWire),
      { accepted: false, calls: 0 }
    );
  } finally {
    Object.defineProperty(hashPrototype, "digest", digestDescriptor);
  }
  assert.equal(poisonCalls, 0);
});

test("all nested transcript mutations deny before signer dispatch", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => {
    calls += 1;
    assert.fail("mutated transcript reached signer");
  });
  const input = JSON.parse(
    sourceVector.preacceptedEnrollmentVerificationInputWire
  );
  const context = JSON.parse(input.context);
  const enrollment = JSON.parse(input.enrollment);
  const proof = JSON.parse(input.phoneProof);
  const approval = JSON.parse(input.approvalEvent);
  const authorization = JSON.parse(approval.content);
  const preEnrollment = JSON.parse(authorization.preEnrollment);
  const cases = [
    inputWith({ acceptanceId: "00".repeat(32) }),
    inputWith({ context: canonical({ ...context, attemptId: "01".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, subject: "02".repeat(32) }) }),
    inputWith({ context: canonical({ ...context, associationId: "03".repeat(32) }) }),
    inputWith({ enrollment: canonical({ ...enrollment,
      enrollmentChallengeId: "04".repeat(32) }) }),
    inputWith({ enrollment: canonical({ ...enrollment,
      ed25519PublicKey: "05".repeat(32) }) }),
    inputWith({ phoneProof: canonical({ ...proof,
      enrollmentChallengeId: "06".repeat(32) }) }),
    inputWith({ phoneProof: canonical({ ...proof,
      signature: "07".repeat(64) }) }),
    inputWith({ approvalEvent: canonical({ ...approval,
      id: "08".repeat(32) }) }),
    inputWith({ approvalEvent: canonical({ ...approval,
      sig: "09".repeat(64) }) }),
    inputWith({ approvalEvent: canonical({
      ...approval,
      content: canonical({
        ...authorization,
        preEnrollment: canonical({
          ...preEnrollment,
          requestId: "0a".repeat(32)
        })
      })
    }) }),
    sourceVector.enrollmentWire,
    inputWith({ version: 1 })
  ];
  for (const [index, inputWire] of cases.entries()) {
    await assert.rejects(
      server
        .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
          producerInput(server, signingPort, { inputWire }),
          enabled
        ),
      unavailable,
      String(index)
    );
    assert.equal(calls, 0, String(index));
  }
});

test("plain invalid fullProofId rejects with zero signer calls", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const contextWire = canonical({
    ...sourceContext,
    fullProofId: "attacker-selected-invalid-full-proof-id"
  });
  const inputWire = canonical({ ...sourceInput, context: contextWire });
  assert.deepEqual(
    await forgedProducerOutcome(server, inputWire, { contextWire }),
    { accepted: false, calls: 0 }
  );
});

test("plain invalid attemptId rejects with zero signer calls", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const contextWire = canonical({
    ...sourceContext,
    attemptId: "attacker-selected-invalid-attempt-id"
  });
  const inputWire = canonical({ ...sourceInput, context: contextWire });
  assert.deepEqual(
    await forgedProducerOutcome(server, inputWire, { contextWire }),
    { accepted: false, calls: 0 }
  );
});

test("a different explicit context wire denies before signer dispatch", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort, {
        contextWire: change(sourceVector.verificationContextWire, {
          attemptId: "10".repeat(32)
        })
      }),
      enabled
    ));
  assert.equal(calls, 0);
});

test("wrong configuration metadata denies before signer dispatch", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  const cases = [
    { expectedIssuer: "https://other.example" },
    { expectedAudience:
      "https://other.example/internal/v2/social/device-admission/consume" },
    { expectedClientId: "other-client" },
    { expectedServicePrincipal: "other-principal" },
    { expectedPurpose: "other-purpose" },
    { expectedAlgorithm: "PS256" },
    { expectedKid: "other-kid" }
  ];
  for (const changes of cases) {
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, changes),
        enabled
      ));
    assert.equal(calls, 0);
  }
  const wrongKidSigner = signer(
    server,
    () => { calls += 1; return Buffer.alloc(256); },
    { kid: "other-kid" }
  );
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, wrongKidSigner),
      enabled
    ));
  assert.equal(calls, 0);
  denied(() => signer(server, () => Buffer.alloc(256), { algorithm: "PS256" }));
});

test("issuer and signer agreement cannot override the signed context audience", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const wrongIssuer = "https://other.example";
  const signingPort = signer(
    server,
    () => {
      calls += 1;
      return Buffer.alloc(256);
    },
    { issuer: wrongIssuer }
  );
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort, { expectedIssuer: wrongIssuer }),
      enabled
    ));
  assert.equal(calls, 0);
});

test("the gate defaults off and accepts literal true only", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.equal(
    server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENTS_V2_ENABLED_DEFAULT,
    false
  );
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  const input = producerInput(server, signingPort);
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(input));
  for (const option of [
    { preacceptedEnrollmentVerificationStatementsV2Enabled: false },
    { preacceptedEnrollmentVerificationStatementsV2Enabled: 1 },
    { preacceptedEnrollmentVerificationStatementsV2Enabled: "true" },
    { preacceptedEnrollmentVerificationStatementsV2Enabled: new Boolean(true) },
    {},
    { preacceptedEnrollmentVerificationStatementsV2Enabled: true, extra: true }
  ]) await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      input,
      option
    ));
  assert.equal(calls, 0);
});

test("zero, oversized, expired and unsafe times deny before signing", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  assert.equal(
    server.MAX_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_LIFETIME_MS,
    10_000
  );
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  const cases = [
    { statementLifetimeMs: 0 },
    { statementLifetimeMs: 10_001 },
    { statementLifetimeMs: -1 },
    { statementLifetimeMs: 1.5 },
    { statementLifetimeMs: "9000" },
    { now: Number.MAX_SAFE_INTEGER },
    { now: Number.MAX_SAFE_INTEGER + 1 },
    { now: -1 },
    { now: JSON.parse(sourceVector.enrollmentWire).issuedAt - 1 },
    { now: JSON.parse(sourceVector.enrollmentWire).expiresAt },
    { phoneSessionExpiresAtMs: 0 },
    { phoneSessionExpiresAtMs: deadlines.now },
    { phoneSessionExpiresAtMs: Number.MAX_SAFE_INTEGER + 1 },
    { approverSessionExpiresAtMs: deadlines.now },
    { fullExpiresAtMs: deadlines.now },
    { x25519BindingExpiresAtMs: deadlines.x25519BindingExpiresAtMs - 1 }
  ];
  for (const changes of cases) {
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, changes),
        enabled
      ));
    assert.equal(calls, 0);
  }
});

test("every transcript and injected deadline bounds the complete interval", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  for (const changes of [
    { now: deadlines.phoneSessionExpiresAtMs - 1, statementLifetimeMs: 2 },
    { now: deadlines.approverSessionExpiresAtMs - 1, statementLifetimeMs: 2 },
    { now: deadlines.fullExpiresAtMs - 1, statementLifetimeMs: 2 }
  ]) {
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, changes),
        enabled
      ));
    assert.equal(calls, 0);
  }
});

test("phone, approver and Full deadlines fail independently before transcript expiry", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const transcriptExpiry = JSON.parse(sourceVector.enrollmentWire).expiresAt;
  const isolatedCases = [
    ["phoneSessionExpiresAtMs", deadlines.now + 10_000],
    ["approverSessionExpiresAtMs", deadlines.now + 20_000],
    ["fullExpiresAtMs", deadlines.now + 30_000]
  ];
  let calls = 0;
  const signingPort = signer(server, () => {
    calls += 1;
    assert.fail("isolated expired deadline reached signer");
  });
  for (const [field, targetDeadline] of isolatedCases) {
    assert.equal(targetDeadline < transcriptExpiry, true, field);
    const changes = {
      phoneSessionExpiresAtMs: transcriptExpiry,
      approverSessionExpiresAtMs: transcriptExpiry,
      fullExpiresAtMs: transcriptExpiry,
      now: targetDeadline - 1,
      statementLifetimeMs: 2,
      [field]: targetDeadline
    };
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort, changes),
        enabled
      ));
    assert.equal(calls, 0, field);
  }
});

test("signer exceptions and malformed outputs deny through one error", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const accessorBytes = new Uint8Array(256);
  Object.defineProperty(accessorBytes, "extra", {
    enumerable: true,
    get() { assert.fail("signature getter invoked"); }
  });
  const outputs = [
    () => { throw new Error("sensitive"); },
    () => new Uint8Array(),
    () => "not-bytes",
    () => new Uint8Array(255),
    () => new Uint8Array(1_025),
    () => new Proxy(new Uint8Array(256), {}),
    () => new (class extends Uint8Array {})(256),
    () => accessorBytes
  ];
  for (const output of outputs) {
    let calls = 0;
    const signingPort = signer(server, (...args) => {
      calls += 1;
      return output(...args);
    });
    await deniedAsync(() => server
      .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
        producerInput(server, signingPort),
        enabled
      ));
    assert.equal(calls, 1);
  }
});

test("a rejected asynchronous signer result is normalized after one call", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => {
    calls += 1;
    return Promise.reject(new Error("sensitive async signer rejection"));
  });
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort),
      enabled
    ));
  assert.equal(calls, 1);
});

test("closed records reject getters, proxies, inherited members and clones", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  const accessor = producerInput(server, signingPort);
  Object.defineProperty(accessor, "now", {
    enumerable: true,
    get() { assert.fail("producer getter invoked"); }
  });
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      accessor,
      enabled
    ));
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      Object.create(producerInput(server, signingPort)),
      enabled
    ));
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      new Proxy({}, { ownKeys() { assert.fail("producer proxy trap invoked"); } }),
      enabled
    ));
  for (const replacement of [
    { ...signingPort },
    Object.freeze({ ...signingPort }),
    new Proxy(signingPort, {})
  ]) await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, replacement),
      enabled
    ));
  assert.equal(calls, 0);

  const signerInput = {
    algorithm: "RS256",
    audience: configuration.audience,
    clientId: configuration.clientId,
    issuer: configuration.issuer,
    kid: configuration.kid,
    purpose:
      server.PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2_PURPOSE,
    servicePrincipal: configuration.servicePrincipal,
    signExact: () => Buffer.alloc(256)
  };
  Object.defineProperty(signerInput, "kid", {
    enumerable: true,
    get() { assert.fail("signer getter invoked"); }
  });
  denied(() => server
    .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2(
      signerInput
    ));
  denied(() => server
    .createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2(
      new Proxy({}, { ownKeys() { assert.fail("signer proxy trap invoked"); } })
    ));
});

test("caller booleans and cloned or forged cryptographic evidence cannot substitute", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const verifier = await import(
    "../src/server/messaging-device-preaccepted-enrollment-v2.mjs"
  );
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  for (const addition of [
    { verified: true },
    { accepted: true },
    { cryptographicEvidence: {} },
    { verificationResult: { authority: "not-granted" } },
    { acceptanceId: sourceVector.acceptanceId },
    { associationId: sourceVector.associationId },
    { attemptId: JSON.parse(sourceVector.verificationContextWire).attemptId },
    { enrollmentChallengeId: JSON.parse(sourceVector.enrollmentWire)
      .enrollmentChallengeId },
    { inputDigest: sourceVector.preacceptedEnrollmentVerificationInputDigest }
  ]) await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      { ...producerInput(server, signingPort), ...addition },
      enabled
    ));
  assert.equal(calls, 0);

  const authentic = await verifier.verifyMessagingDevicePreacceptedEnrollmentV2(
    sourceVector.preacceptedEnrollmentVerificationInputWire
  );
  for (const forged of [
    { ...authentic },
    structuredClone(authentic),
    Object.create(authentic),
    Object.freeze({ ...authentic }),
    new Proxy(authentic, {})
  ]) assert.throws(
    () => verifier.projectMessagingDevicePreacceptedEnrollmentV2(forged),
    verifierUnavailable
  );
});

test("V1 and V2 remain separate closed protocols with no fallback", async (t) => {
  const server = await loadServer(t);
  if (!server) return;
  const verifier = await import(
    "../src/server/messaging-device-preaccepted-enrollment-v2.mjs"
  );
  const v1Protocol = await import(
    "../src/server/messaging-device-verification-statement-v1.mjs"
  );
  const v1Fixture = JSON.parse(await readFile(new URL(
    "./fixtures/social_device_admission_v1.json",
    import.meta.url
  )));
  const v1 = v1Fixture.vectors.enrollmentV2;
  assert.throws(
    () => v1Protocol.parseMessagingDeviceVerificationInputV1(
      sourceVector.preacceptedEnrollmentVerificationInputWire
    ),
    v1Unavailable
  );
  await assert.rejects(
    verifier.verifyMessagingDevicePreacceptedEnrollmentV2(v1.inputWire),
    verifierUnavailable
  );
  let calls = 0;
  const signingPort = signer(server, () => { calls += 1; return Buffer.alloc(256); });
  await deniedAsync(() => server
    .produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2(
      producerInput(server, signingPort, {
        contextWire: v1.contextWire,
        inputWire: v1.inputWire
      }),
      enabled
    ));
  assert.equal(calls, 0);
});

test("the V2 producer remains absent from runtime, route, BFF, config, browser and UI graphs", async () => {
  const moduleName = "messaging-device-preaccepted-verification-statement-v2";
  for (const relative of [
    "../scripts/hodlxxi-social-server.mjs",
    "../src/server/social-mobile-runtime-v1.mjs",
    "../src/server/social-mobile-composition-v1.mjs",
    "../src/server/social-mobile-bff-v1.mjs",
    "../src/server/social-oauth-bff.mjs",
    "../src/server/social-oauth-config.mjs",
    "../web/auth-entry.mjs",
    "../web/social-mobile-browser-v1.mjs",
    "../web/social-mobile-ui-v1.mjs"
  ]) {
    const source = await readFile(new URL(relative, import.meta.url), "utf8");
    assert.equal(source.includes(moduleName), false, relative);
  }
});

test("the producer has no direct storage, network or key-discovery I/O", async () => {
  const source = await readFile(new URL(
    "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs",
    import.meta.url
  ), "utf8");
  assert.doesNotMatch(source,
    /node:(?:fs|net|http|https)|postgres|redis|socket|fetch\s*\(|readFile|openFile|createPrivateKey|PRIVATE KEY|process\.env|WebSocket/);
  assert.doesNotMatch(source,
    /admitMessagingDeviceRequestV1|currentFull\s*:\s*true|runtimeEnabled\s*:\s*true/);
  assert.match(source, /const safeBuffer = Buffer;/);
  assert.match(source, /const safeCreateHash = createHash;/);
  assert.match(source, /const safeIsProxy = isProxy;/);
  const afterBuiltinCaptures = source.slice(
    source.indexOf("const safeIsProxy = isProxy;") +
      "const safeIsProxy = isProxy;".length
  );
  assert.doesNotMatch(afterBuiltinCaptures, /\b(?:Buffer|createHash|isProxy)\b/);
  assert.match(source, /const safeApply = Reflect\.apply;/);
  assert.match(source, /const safeWeakMapSet = WeakMap\.prototype\.set;/);
  assert.match(source, /const safeWeakMapHas = WeakMap\.prototype\.has;/);
  assert.match(source, /const safeWeakMapGet = WeakMap\.prototype\.get;/);
  assert.match(source, /suppliedSignature = await safeApply\(/);
  assert.doesNotMatch(source, /await Reflect\.apply\(|signerStates\.(?:set|has|get)\(/);
});

test("the public RSA JWK has the exact public-only member set", () => {
  const jwk = statementFixture.publicVerificationMaterial.jwk;
  assert.deepEqual(Object.keys(jwk).sort(), [
    "alg", "e", "kid", "kty", "n", "use"
  ]);
  for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
    assert.equal(Object.hasOwn(jwk, member), false, member);
  }
});

test("the public fixture contains no serialized private RSA key", () => {
  const source = statementFixtureBytes.toString("utf8");
  assert.doesNotMatch(source,
    /-----BEGIN (?:RSA )?PRIVATE KEY-----|privateKey|secretKey|seed|mnemonic/);
});
