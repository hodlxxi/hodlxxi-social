// Source-only canonical bytes for a new registered-device possession domain.
// No network, credential issuance, admission or runtime enablement.
import { canonical, exact, parseClosedJson } from "./social-mobile-protocol-v1.mjs";

export const REGISTERED_DEVICE_SESSION_RUNTIME_ENABLED = false;
export const CHALLENGE_SCHEMA = "hodlxxi.social_registered_device_session_challenge.v1";
export const PROOF_SCHEMA = "hodlxxi.social_registered_device_session_proof.v1";
export const CHALLENGE_DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_CHALLENGE_V1";
export const PROOF_DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_PROOF_V1";
const HEX_FIELDS = ["associationId", "bindingId", "challengeId", "contextCommitment", "deviceId", "ed25519PublicKey", "subject"];
const FIELDS = [...HEX_FIELDS, "associationVersion", "audience", "authorityEpoch", "bindingVersion", "clientId", "domain",
  "expiresAt", "issuedAt", "issuer", "schema", "version", "x25519PublicKeyCommitment"];
const PROOF_FIELDS = ["challengeId", "schema", "signature", "version"];
const fail = () => { throw new TypeError("registered device session proof unavailable"); };
const hex = (value, length) => typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const origin = value => {
  // Deliberately DNS-only v1, byte-identical to UBID's shape contract.
  if (typeof value !== "string" || value.length < 1 || value.length > 255 || /[^\x21-\x7e]/.test(value)) return false;
  const match = /^https:\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$/.exec(value);
  if (!match) return false;
  const [, host, port] = match;
  const labels = host.split(".");
  return (port === undefined || Number(port) <= 65535 && port !== "443") &&
    !/^(?:[0-9]+|0x[0-9a-f]*)$/.test(labels.at(-1)) &&
    labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) && !label.startsWith("xn--"));
};
export function parseRegisteredDeviceSessionChallengeV1(wire) {
  try {
    const v = exact(parseClosedJson(wire, { canonicalOnly: true, maximum: 4096 }), FIELDS);
    if (v.schema !== CHALLENGE_SCHEMA || v.version !== 1 || v.domain !== CHALLENGE_DOMAIN ||
        !HEX_FIELDS.every(field => hex(v[field], 64)) || v.ed25519PublicKey === v.subject ||
        !origin(v.issuer) || !origin(v.audience) || typeof v.clientId !== "string" ||
        /[^\x21-\x7e]/.test(v.clientId) || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(v.clientId) ||
        typeof v.x25519PublicKeyCommitment !== "string" ||
        v.x25519PublicKeyCommitment.length !== 117 ||
        !/^hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}$/.test(v.x25519PublicKeyCommitment) ||
        !["issuedAt", "expiresAt", "associationVersion", "authorityEpoch", "bindingVersion"].every(field => integer(v[field])) ||
        v.bindingVersion < 1 || v.bindingVersion > 1024 || v.associationVersion < 1 || v.associationVersion > v.authorityEpoch ||
        v.expiresAt <= v.issuedAt || v.expiresAt - v.issuedAt > 60000) fail();
    return Object.freeze(v);
  } catch { fail(); }
}
export function requireCurrentRegisteredDeviceSessionChallengeV1(wire, { issuer, audience, clientId, contextCommitment, now }) {
  const v = parseRegisteredDeviceSessionChallengeV1(wire);
  if (!integer(now) || now < v.issuedAt || now >= v.expiresAt ||
      v.issuer !== issuer || v.audience !== audience || v.clientId !== clientId || v.contextCommitment !== contextCommitment) fail();
  return v;
}
export function registeredDeviceSessionSigningPreimageV1(wire) {
  parseRegisteredDeviceSessionChallengeV1(wire);
  return new TextEncoder().encode(PROOF_DOMAIN + "\0" + wire);
}
export function parseRegisteredDeviceSessionProofV1(wire, challengeWire) {
  try {
    const challenge = parseRegisteredDeviceSessionChallengeV1(challengeWire);
    const v = exact(parseClosedJson(wire, { canonicalOnly: true, maximum: 4096 }), PROOF_FIELDS);
    if (v.schema !== PROOF_SCHEMA || v.version !== 1 || v.challengeId !== challenge.challengeId || !hex(v.signature, 128)) fail();
    return Object.freeze(v);
  } catch { fail(); }
}
export function createRegisteredDeviceSessionProofWireV1(challengeWire, signature) {
  const challenge = parseRegisteredDeviceSessionChallengeV1(challengeWire);
  const wire = canonical({ challengeId: challenge.challengeId, schema: PROOF_SCHEMA, signature, version: 1 });
  parseRegisteredDeviceSessionProofV1(wire, challengeWire);
  return wire;
}
