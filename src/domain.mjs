export const AccessStatus = Object.freeze({ LIMITED: "limited", FULL: "full", OPERATOR: "operator" });
export const EdgeType = Object.freeze({ FRIEND: "friend", SPONSOR_TRUST: "sponsor-trust" });

export function normalizePublicKey(value) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) throw new TypeError("public key must be 64 hexadecimal characters");
  return value.toLowerCase();
}

export function participant({ publicKey, displayName }) {
  return Object.freeze({ id: normalizePublicKey(publicKey), publicKey: normalizePublicKey(publicKey), displayName: String(displayName || "Participant") });
}

export function relationship(type, from, to) {
  if (!Object.values(EdgeType).includes(type)) throw new TypeError("unsupported relationship type");
  return Object.freeze({ type, from: normalizePublicKey(from), to: normalizePublicKey(to) });
}

export function deriveAccess(publicKey, assertion, now) {
  let subject;
  try { subject = normalizePublicKey(publicKey); } catch { return AccessStatus.LIMITED; }
  if (!Number.isFinite(now)) return AccessStatus.LIMITED;
  if (!assertion || assertion.source !== "hodlxxi-crt" || assertion.version !== 1 || !Number.isFinite(assertion.expiresAt) || assertion.expiresAt <= now) return AccessStatus.LIMITED;
  try { if (normalizePublicKey(assertion.subject) !== subject) return AccessStatus.LIMITED; } catch { return AccessStatus.LIMITED; }
  if (assertion.status === AccessStatus.FULL || assertion.status === AccessStatus.OPERATOR) return assertion.status;
  return AccessStatus.LIMITED;
}
