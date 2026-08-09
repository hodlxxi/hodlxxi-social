import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { assertions, keys } from "../src/fixtures.mjs";
import { createComposedSocialDataService } from "../src/data/composition.mjs";
import { HodlxxiAuthorityReadAdapter } from "../src/data/hodlxxi-authority-read-adapter.mjs";
import { NostrPublicReadAdapter } from "../src/data/nostr-public-read-adapter.mjs";
import { SyntheticSocialAdapter } from "../src/data/synthetic-adapter.mjs";

const authority = (readAssertion) => new HodlxxiAuthorityReadAdapter({ readAssertion });
const assertion = (status, overrides = {}) => ({
  source: "hodlxxi-crt", version: 1, subject: keys.cy, status, expiresAt: 200,
  evidenceRef: `crt-evidence:${status}`, ...overrides
});

test("composition requires an explicitly selected social adapter and is deterministic", () => {
  assert.throws(() => createComposedSocialDataService(), /explicitly selected/);
  assert.throws(() => createComposedSocialDataService({}), /explicitly selected/);
  const selected = { socialAdapter: new SyntheticSocialAdapter(keys.ben), authorityAdapter: authority((subject) => assertions[subject]) };
  assert.deepEqual(createComposedSocialDataService(selected).load(), createComposedSocialDataService(selected).load());
});

test("synthetic social state cannot overwrite explicitly selected authority", () => {
  const socialAdapter = new SyntheticSocialAdapter(keys.cy);
  const data = createComposedSocialDataService({
    socialAdapter,
    authorityAdapter: authority((subject) => subject === keys.cy ? assertion(AccessStatus.LIMITED) : undefined)
  }).load();
  assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
  assert.deepEqual(data.externalAssertions[keys.cy], {
    subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "hodlxxi-crt", valid: true,
    evidenceRef: "crt-evidence:limited"
  });
  assert.equal(data.friendEdges.length > 0, true);
  assert.equal(data.sponsorTrustEdges.length > 0, true);
});

test("valid HODLXXI levels retain provenance and evidence independent of social ordering", () => {
  for (const status of Object.values(AccessStatus)) {
    const data = createComposedSocialDataService({
      authorityAdapter: authority((subject) => subject === keys.cy ? assertion(status) : undefined),
      socialAdapter: new SyntheticSocialAdapter(keys.cy),
      now: 100
    }).load();
    assert.deepEqual(data.externalAssertions[keys.cy], {
      subject: keys.cy, assertedStatus: status, source: "hodlxxi-crt", valid: true,
      evidenceRef: `crt-evidence:${status}`
    });
    assert.equal(data.statuses[keys.cy], status);
  }
});

test("authority failures fail closed without discarding usable social data", () => {
  const adapters = [
    undefined,
    authority(() => { throw new Error("offline"); }),
    authority(() => assertion(AccessStatus.OPERATOR, { expiresAt: 100 })),
    authority(() => assertion(AccessStatus.OPERATOR, { source: "nostr" })),
    authority(() => ({ status: AccessStatus.OPERATOR }))
  ];
  for (const authorityAdapter of adapters) {
    const data = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(keys.cy), authorityAdapter }).load();
    assert.equal(data.participants.length, 4);
    assert.equal(data.notes.length > 0, true);
    assert.equal(data.statuses[keys.cy], AccessStatus.LIMITED);
    assert.deepEqual(data.externalAssertions[keys.cy], {
      subject: keys.cy, assertedStatus: AccessStatus.LIMITED, source: "unavailable", valid: false
    });
  }
});

test("normalized Nostr social data remains usable while authority fails closed", async () => {
  const note = {
    id: "e".repeat(64), pubkey: keys.ada, created_at: 1, kind: 1, tags: [], content: "public note",
    sig: "f".repeat(128)
  };
  const profile = {
    ...note, id: "d".repeat(64), kind: 0,
    content: JSON.stringify({ display_name: "Ada", status: "operator", source: "hodlxxi-crt" })
  };
  const socialAdapter = await NostrPublicReadAdapter.create({ viewerId: keys.ada, transport: { read: () => [profile, note] } });
  const data = createComposedSocialDataService({
    socialAdapter,
    authorityAdapter: authority(() => { throw new Error("offline"); })
  }).load();
  assert.equal(data.notes[0].body, "public note");
  assert.equal(data.statuses[keys.ada], AccessStatus.LIMITED);
  for (const field of ["sig", "tags", "kind", "pubkey", "created_at"]) assert.equal(field in data.notes[0], false);
  assert.equal("status" in data.participants[0], false);
  assert.equal("source" in data.participants[0], false);

  const authoritative = createComposedSocialDataService({
    socialAdapter,
    authorityAdapter: authority((subject) => subject === keys.ada ? assertion(AccessStatus.FULL, { subject: keys.ada }) : undefined)
  }).load();
  assert.equal(authoritative.statuses[keys.ada], AccessStatus.FULL);
  assert.equal(authoritative.externalAssertions[keys.ada].source, "hodlxxi-crt");
});

test("composition exposes no capability union, connector, hidden selection, or mutation path", async () => {
  const source = await readFile(new URL("../src/data/composition.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /process\.env|location|hostname|document|window|WebSocket|fetch\(|XMLHttpRequest|request\s*\(|password|token|secret|private.?key|publish|\bsign|grant|operator|issueCRT|bitcoin|lightning|capabilities/i);
  const service = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter() });
  assert.equal(service.capabilities, undefined);
  for (const operation of ["writeAssertion", "issueCRT", "grantFull", "grantOperator", "sign", "publish", "request"]) assert.equal(service[operation], undefined);
});
