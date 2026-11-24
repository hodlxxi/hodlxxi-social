// Strict cryptographic verification only. A verified signature is NOT admission.
// A future UBID owner must issue/lock/consume the exact stored challenge and
// recheck current registration and Full before creating any credential.
import {
  parseRegisteredDeviceSessionProofV1,
  registeredDeviceSessionSigningPreimageV1,
  requireCurrentRegisteredDeviceSessionChallengeV1
} from "../../web/registered-device-session-v1.mjs";
import { strictVerifyMessagingDeviceEd25519V1 } from "./messaging-device-proof-profile-v1.mjs";

export function verifyRegisteredDeviceSessionProofV1({ challengeWire, proofWire, issuer, audience, clientId, contextCommitment, now }) {
  try {
    const challenge = requireCurrentRegisteredDeviceSessionChallengeV1(challengeWire, {
      issuer, audience, clientId, contextCommitment, now
    });
    const proof = parseRegisteredDeviceSessionProofV1(proofWire, challengeWire);
    return strictVerifyMessagingDeviceEd25519V1(
      registeredDeviceSessionSigningPreimageV1(challengeWire), challenge.ed25519PublicKey, proof.signature
    ) === true;
  } catch { return false; }
}
