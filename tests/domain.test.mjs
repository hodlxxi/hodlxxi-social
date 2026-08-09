import test from "node:test";
import assert from "node:assert/strict";
import { AccessStatus, EdgeType, deriveAccess, normalizePublicKey, participant, relationship } from "../src/domain.mjs";

const a = "a".repeat(64); const b = "b".repeat(64);
test("public keys normalize and identify participants", () => {
  assert.equal(normalizePublicKey("A".repeat(64)), a);
  assert.equal(participant({ publicKey: a, displayName: "Alias" }).id, a);
  assert.throws(() => normalizePublicKey("not-a-key"));
});
test("external assertions fail closed", () => {
  const assertion = (overrides = {}) => ({ source: "hodlxxi-crt", version: 1, subject: a, status: "full", expiresAt: 20, ...overrides });
  assert.equal(deriveAccess(a, null, 10), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion()), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion(), Number.NaN), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion(), Number.POSITIVE_INFINITY), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion(), Number.NEGATIVE_INFINITY), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion({ expiresAt: 9 }), 10), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion({ source: "social", status: "operator" }), 10), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion({ version: 2 }), 10), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion({ subject: b }), 10), AccessStatus.LIMITED);
  assert.equal(deriveAccess(a, assertion(), 10), AccessStatus.FULL);
  assert.equal(deriveAccess(a, assertion({ status: "operator" }), 10), AccessStatus.OPERATOR);
});
test("friend and sponsor trust remain distinct", () => {
  assert.notDeepEqual(relationship(EdgeType.FRIEND, a, b), relationship(EdgeType.SPONSOR_TRUST, a, b));
});
