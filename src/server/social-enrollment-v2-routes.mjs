// Fixed route vocabulary; no runtime, crypto or I/O construction.
export const ENROLLMENT_BROWSER_PREFIX = "/auth/enrollment/v2";
export const ENROLLMENT_CONTEXT_COOKIE = "__Host-hodlxxi-social-enrollment-v2";
export const ENROLLMENT_CSRF_HEADER = "x-hodlxxi-enrollment-csrf";
export const commands = Object.freeze({ context: ["role"], create: [], offer: ["qr"],
  propose: ["qr", "authorizationWire", "possessionProof"], inspect: ["pairingId"],
  approve: ["pairingId", "approvalWire", "comparisonCode"], status: ["pairingId"],
  issue: ["pairingId", "secret", "possessionProof", "verifier", "deliveryKey"],
  recover: ["pairingId", "secret", "possessionProof", "verifier", "deliveryKey"],
  challenge: [], complete: ["phoneProofWire"], cancel: ["pairingId"], logout: [] });
export const ENROLLMENT_BROWSER_POST_ROUTES = Object.freeze(Object.keys(commands).map((name) => ENROLLMENT_BROWSER_PREFIX + "/" + name));
