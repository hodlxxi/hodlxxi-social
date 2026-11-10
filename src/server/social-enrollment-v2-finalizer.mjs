import { FinalizeOutcomeUnknown } from "./ubid-social-enrollment-v2-client.mjs";
// Server-only orchestration. A receipt records registration; it grants no Send.
import { createPublicKey, verify } from "node:crypto";
import { canonical, exact, parseClosedJson } from "../../web/social-mobile-protocol-v1.mjs";
import { DEADLINE_FIELDS } from "./enrollment-v2-deadline-fields.mjs";
import { verifyMessagingDevicePreacceptedEnrollmentV2, projectMessagingDevicePreacceptedEnrollmentV2 }
  from "./messaging-device-preaccepted-enrollment-v2.mjs";
import { produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2 as produce }
  from "./messaging-device-preaccepted-verification-statement-v2.mjs";

const fail = () => { throw new TypeError("device registration unavailable"); };
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const decode = (value) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) fail();
  return bytes;
};

export function verifyEnrollmentDeadlineEvidence(compact, { trust, expected, now }) {
  try {
    if (typeof compact !== "string" || compact.length > 16384 || !integer(now)) fail();
    const chunks = compact.split("."); if (chunks.length !== 3) fail();
    const [h, p, s] = chunks;
    const header = exact(parseClosedJson(new TextDecoder("utf-8", { fatal: true }).decode(decode(h)),
      { canonicalOnly: true }), ["alg", "kid", "typ"]);
    if (header.alg !== "RS256" || header.kid !== trust.publicJwk.kid ||
        header.typ !== "hodlxxi-social-messaging-device-verification-deadline-evidence-v1+jws") fail();
    const key = createPublicKey({ key: trust.publicJwk, format: "jwk" });
    if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength < 2048 ||
        verify("RSA-SHA256", Buffer.from(h + "." + p, "ascii"), key, decode(s)) !== true) fail();
    const value = exact(parseClosedJson(new TextDecoder("utf-8", { fatal: true }).decode(decode(p)),
      { canonicalOnly: true, maximum: 12288 }), DEADLINE_FIELDS);
    if (value.schema !== "hodlxxi.social_messaging_device_verification_deadline_evidence.v1" || value.version !== 1 ||
        value.freshnessProfile !== "native-v2-60s-v1" ||
        value.purpose !== "social_messaging_device_verification_deadline_evidence_v1" || value.operation !== "register" ||
        value.iss !== expected.issuer || value.aud !== expected.audience ||
        value.clientId !== expected.clientId || value.servicePrincipal !== expected.servicePrincipal ||
        value.subject !== expected.subject || value.socialSessionIssuanceId !== expected.issuanceId ||
        value.acceptanceId !== expected.acceptanceId || value.inputDigest !== expected.inputDigest ||
        value.enrollmentChallengeId !== expected.challengeId || value.associationId !== expected.associationId ||
        value.reservationId !== expected.reservationId || value.reservationRevision !== 1 ||
        value.observedAt !== expected.observedAt || value.expiresAt !== expected.expiresAt) fail();
    for (const field of ["observedAt", "expiresAt", "phoneSessionExpiresAt", "approverSessionExpiresAt",
      "fullExpiresAt", "x25519BindingExpiresAt"]) if (!integer(value[field])) fail();
    if (!(trust.notBefore <= value.observedAt && value.observedAt <= now && now < value.expiresAt &&
        value.expiresAt <= trust.notAfter && value.expiresAt - value.observedAt <= 60000 &&
        value.expiresAt <= Math.min(value.phoneSessionExpiresAt, value.approverSessionExpiresAt,
          value.fullExpiresAt, value.x25519BindingExpiresAt)) || trust.revokedAt !== null) fail();
    return Object.freeze(value);
  } catch { fail(); }
}

export function createEnrollmentFinalizer({ client, signer, evidenceTrust, issuer, socialOrigin,
  clientId, servicePrincipal, now = Date.now }) {
  return async function complete(state, { phone, challenge, phoneProofWire }) {
    try {
      const wire = canonical({ acceptanceId: phone.acceptanceId, approvalEvent: challenge.approvalEventWire,
        context: challenge.contextWire, enrollment: challenge.enrollmentWire, phoneProof: phoneProofWire,
        schema: "hodlxxi.social_preaccepted_enrollment_verification_input.v2", version: 2 });
      // Real BIP340 and Ed25519 verification precedes even reservation traffic.
      const verified = await verifyMessagingDevicePreacceptedEnrollmentV2(wire);
      const projection = projectMessagingDevicePreacceptedEnrollmentV2(verified);
      const context = parseClosedJson(challenge.contextWire, { canonicalOnly: true });
      if (projection.subject !== phone.subject || projection.acceptanceId !== phone.acceptanceId ||
          context.subject !== phone.subject) fail();
      if (state.inputWire !== undefined && state.inputWire !== wire) fail();
      state.inputWire = wire;
      if (state.reservation === undefined) {
        state.reservation = await client.reserve({ body: { issuanceId: phone.issuanceId, verificationInputWire: wire },
          viewerAccessToken: phone.viewerAccessToken });
      }
      const reserved = state.reservation;
      if (state.statement === undefined) {
        const at = now();
        const trust = evidenceTrust.find((r) => r.publicJwk.kid === JSON.parse(
          decode(reserved.evidenceCompactJws.split(".")[0]).toString("utf8")).kid);
        if (!trust) fail();
        const claims = verifyEnrollmentDeadlineEvidence(reserved.evidenceCompactJws, { trust, now: at,
          expected: { issuer, audience: socialOrigin + "/internal/v1/social/messaging-device-verification/deadline-evidence/consume",
            clientId, servicePrincipal, subject: phone.subject, issuanceId: phone.issuanceId,
            acceptanceId: phone.acceptanceId, inputDigest: projection.inputDigest, challengeId: context.challengeId,
            associationId: projection.associationId, reservationId: reserved.reservationId,
            observedAt: reserved.observedAt, expiresAt: reserved.expiresAt } });
        const lifetime = Math.min(60000, claims.expiresAt - at);
        if (!integer(lifetime) || lifetime < 1) fail();
        state.statement = await produce({ inputWire: wire, contextWire: challenge.contextWire,
          expectedAlgorithm: "RS256", expectedAudience: issuer + "/internal/v2/social/device-admission/consume",
          expectedClientId: clientId, expectedIssuer: socialOrigin, expectedKid: signer.kid,
          expectedPurpose: "social_preaccepted_enrollment_cryptographic_verification_v2",
          expectedServicePrincipal: servicePrincipal, now: at, statementLifetimeMs: lifetime,
          phoneSessionExpiresAtMs: claims.phoneSessionExpiresAt,
          approverSessionExpiresAtMs: claims.approverSessionExpiresAt,
          fullExpiresAtMs: claims.fullExpiresAt, x25519BindingExpiresAtMs: claims.x25519BindingExpiresAt, signer },
          { preacceptedEnrollmentVerificationStatementsV2Enabled: true });
      }
      const request = { body: { issuanceId: phone.issuanceId, reservationId: reserved.reservationId, reservationRevision: "1",
        verificationInputWire: wire, evidenceCompactJws: reserved.evidenceCompactJws, statementCompactJws: state.statement },
        viewerAccessToken: phone.viewerAccessToken };
      try { return await client.finalize(request); }
      catch (error) {
        if (!(error instanceof FinalizeOutcomeUnknown) && !state.outcomeUnknown) throw error;
        state.outcomeUnknown = true;
        // One bounded exact retry; UBID authenticates the original signed evidence
        // and returns retained history or applies the original operation atomically.
        try { return await client.finalize(request); } catch { throw new FinalizeOutcomeUnknown(); }
      }
    } catch (error) { if (error instanceof FinalizeOutcomeUnknown || state.outcomeUnknown) throw new FinalizeOutcomeUnknown(); fail(); }
  };
}
