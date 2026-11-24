// Source-only purpose-separated statement. No session is granted here.
// The caller supplies an operator-held signing key, never a browser key.
import { sign } from "node:crypto";
import { canonical } from "../../web/social-mobile-protocol-v1.mjs";
import { verifyRegisteredDeviceSessionProofV1 } from "./registered-device-session-proof-v1.mjs";

const DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_STATEMENT_V1";
const SCHEMA = "hodlxxi.social_registered_device_session_statement.v1";
const fail = () => { throw new TypeError("registered device statement unavailable"); };

export function produceRegisteredDeviceSessionStatementV1(input, { kid, privateKey } = {}) {
  try {
    if (typeof kid !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(kid) ||
        privateKey?.type !== "private" || privateKey.asymmetricKeyType !== "rsa" ||
        privateKey.asymmetricKeyDetails?.modulusLength < 2048 ||
        privateKey.asymmetricKeyDetails?.modulusLength > 8192 ||
        !verifyRegisteredDeviceSessionProofV1(input)) fail();
    const preimage = DOMAIN + "\0" + canonical({
      challenge: input.challengeWire, proof: input.proofWire, kid, schema: SCHEMA
    });
    const signature = sign("RSA-SHA256", Buffer.from(preimage, "ascii"), privateKey).toString("hex");
    return canonical({ kid, schema: SCHEMA, signature });
  } catch { fail(); }
}
