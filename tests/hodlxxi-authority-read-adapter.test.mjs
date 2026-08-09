import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { keys } from "../src/fixtures.mjs";
import { SocialCapability } from "../src/data/capabilities.mjs";
import { HodlxxiAuthorityReadAdapter } from "../src/data/hodlxxi-authority-read-adapter.mjs";
import { createSocialDataService } from "../src/data/service.mjs";
import { SyntheticSocialAdapter } from "../src/data/synthetic-adapter.mjs";

const assertion = (status, overrides = {}) => ({
  source: "hodlxxi-crt", version: 1, subject: keys.cy, status, expiresAt: 200,
  evidenceRef: `crt-evidence:${status}`, ...overrides
});

const load = (authorityAdapter, now = 100) => createSocialDataService(new SyntheticSocialAdapter(keys.cy), { authorityAdapter, now }).load();

test("adapter exposes one explicit read-only authority capability", () => {
  const calls = [];
  const adapter = new HodlxxiAuthorityReadAdapter({ readAssertion: (subject) => { calls.push(subject); return assertion(AccessStatus.LIMITED); } });
  assert.deepEqual(adapter.capabilities, [SocialCapability.READ_EXTERNAL_AUTHORITY]);
  assert.deepEqual(adapter.readAssertion(keys.cy.toUpperCase()), assertion(AccessStatus.LIMITED));
  assert.deepEqual(calls, [keys.cy]);
  assert.equal(Object.isFrozen(adapter), true);
  assert.equal(adapter.transport, undefined);
  for (const method of ["writeAssertion", "issueCRT", "grantFull", "grantOperator", "mutateSponsor", "publish", "sign"]) assert.equal(adapter[method], undefined);
});

test("valid Limited, Full, and Operator assertions preserve provenance and project separately", () => {
  for (const status of Object.values(AccessStatus)) {
    const adapter = new HodlxxiAuthorityReadAdapter({ readAssertion: (subject) => subject === keys.cy ? assertion(status, { subject: keys.cy.toUpperCase() }) : undefined });
    const data = load(adapter);
    assert.deepEqual(data.externalAssertions[keys.cy], {
      subject: keys.cy, assertedStatus: status, source: "hodlxxi-crt", valid: true, evidenceRef: `crt-evidence:${status}`
    });
    assert.equal(data.statuses[keys.cy], status);
  }
});

test("missing and failing transports fail closed without blocking social reads", () => {
  for (const adapter of [
    undefined,
    new HodlxxiAuthorityReadAdapter(),
    new HodlxxiAuthorityReadAdapter({}),
    new HodlxxiAuthorityReadAdapter({ readAssertion: () => { throw new Error("offline"); } })
  ]) {
    const data = load(adapter);
    assert.equal(data.participants.length, 4);
    assert.deepEqual(data.externalAssertions[keys.cy], { subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "unavailable", valid: false });
    assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
  }
  assert.equal(new HodlxxiAuthorityReadAdapter({ readAssertion: () => assertion(AccessStatus.OPERATOR) }).readAssertion("malformed"), undefined);
});

test("malformed or unsupported authority responses cannot elevate", () => {
  const elevated = assertion(AccessStatus.OPERATOR);
  const cases = [
    undefined,
    null,
    "operator",
    { ...elevated, version: 2 },
    { ...elevated, subject: keys.ada },
    { ...elevated, subject: "malformed" },
    { ...elevated, status: "administrator" },
    { ...elevated, source: "nostr" },
    { ...elevated, expiresAt: 100 },
    { ...elevated, evidenceRef: "   " },
    { ...elevated, grant: "operator" }
  ];
  for (const raw of cases) {
    const data = load(new HodlxxiAuthorityReadAdapter({ readAssertion: (subject) => subject === keys.cy ? raw : undefined }));
    assert.deepEqual(data.externalAssertions[keys.cy], { subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "unavailable", valid: false });
    assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
  }
});

test("social and Nostr-shaped state cannot substitute for authority", () => {
  const social = new SyntheticSocialAdapter(keys.ada);
  const data = createSocialDataService(social).load();
  assert.equal(social.capabilities.includes(SocialCapability.READ_EXTERNAL_AUTHORITY), false);
  assert.equal(social.readAssertion, undefined);
  assert.deepEqual(new Set(Object.values(data.statuses)), new Set([AccessStatus.LIMITED]));
});

test("authority adapter source has no live connector, secret, mutation, payment, or key path", async () => {
  const source = await readFile(new URL("../src/data/hodlxxi-authority-read-adapter.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /hodlxxi\.com|WebSocket|fetch\(|XMLHttpRequest|process\.env|localStorage|sessionStorage|indexedDB|password|token|private.?key|POST|PUT|PATCH|DELETE|issueCRT|grantFull|grantOperator|mutateSponsor|bitcoin|lightning|LND|custody/i);
});
