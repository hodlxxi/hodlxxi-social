import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { AUTHORITY_EXIT_CODES, AuthorityProbeError } from "../src/dev/hodlxxi-authority-live-probe.mjs";
import {
  SOCIAL_AUTHORITY_PROJECTION_SCHEMA, createExactSubjectTransport, createExplicitSubjectContext,
  formatSocialAuthorityFailure, formatSocialAuthorityResult, runSocialAuthorityComposition
} from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { runSocialAuthorityCli } from "../scripts/hodlxxi-authority-social-probe.mjs";

const subject = "c".repeat(64);
const options = { origin: "https://authority.example", subject, timeoutMs: 5000 };
const raw = (identityClass = "limited", overrides = {}) => ({
  current_full_relation_satisfied: identityClass === "full", evidence_source: `${identityClass}-evidence`, identity_class: identityClass,
  observed_at: identityClass === "full" ? "2026-08-12T10:11:12+00:00" : null,
  schema: "hodlxxi.current_entitlement_assertion.v1", subject, valid: true, ...overrides
});
const response = (body, status = 200) => {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  return { status, headers: new Headers({ "content-type": "application/json" }), body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }) };
};
const dependencies = (fetchImpl) => ({ fetchImpl, setTimeoutImpl: () => 1, clearTimeoutImpl() {} });
const contentSha256 = (content) => createHash("sha256").update(content, "utf8").digest("hex");
const protectedContentSha256 = Object.freeze({
  "web/index.html": "02f4fe837149801b88a33da49d8f1f68455ad7c80233fb5995d7b160cea75606",
  "web/app.mjs": "da127fe9aaa8e8f0d5a57642a2fa9c1cf1e30233695f6148b8b93ae11a02c974",
  "web/dev-live.html": "0a08b87328f5edecc8ab7f5cd4bf1d6be692725086fd2ea2043f6657e9210bdb",
  "web/dev-live.mjs": "7f6e7023ff5579d5d3d7183e896614a2ab22a81b5c03fb53038cb4de90ba3f88",
  "src/dev/live-social-composition.mjs": "58a74a3aa54ed8b757124b58aac1fc5983b2bda77a1d1c935e5ca7917e445c14",
  "scripts/nostr-relay-probe.mjs": "36848909c4b04ed009c40d531bc78d5f2ab69f7567f5ed48f21dd9f40588fc5e",
  "package.json": "918e7ebbd01966d636b076037d03a73cf928e02d6d4ea3d38167da24ce81bad5",
  "src/dev/hodlxxi-authority-live-probe.mjs": "794de32b78394edae493025c872b0afcbf9335e54c4b5ae6a946b2ea0459b6a4",
  "src/data/normalize.mjs": "8fd7409c127518d8dff8fdf013ff5eb4f45da262ed35a277a5e57931e6d22038",
  "src/data/hodlxxi-authority-read-adapter.mjs": "44d584145047dfed1c5602276a00b41401bbf9e1fb036b8dcdd4ceb279d748bd",
  "src/data/service.mjs": "ab8a4f5c04e6a6884f793ed85a30e8c1e4ceac4e0304dc7aa63c63de6c282031",
  "src/data/composition.mjs": "59109496ad1cdd2c207eb3a0b3694513564b6b4e4c7cc9d67117a1837ca6e27a",
  "src/domain.mjs": "45fd3801d773299c107a54fc56d4d25434a8ad904f2b0525ff7dd271314ec757",
  "src/fixtures.mjs": "7ce91ac3aa6543eb84d9bf80843a28bf29ed023226baa42dfd658e8326d646bc"
});

test("external Full and Limited cross the existing normalized Social boundary exactly once", async () => {
  for (const identityClass of ["limited", "full"]) {
    const calls = [];
    const result = await runSocialAuthorityComposition(options, dependencies(async (...args) => { calls.push(args); return response(raw(identityClass)); }));
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], `https://authority.example/agent/authority/current/${subject}.json`);
    assert.deepEqual({ ...calls[0][1], signal: undefined }, { method: "GET", redirect: "manual", credentials: "omit", headers: { Accept: "application/json" }, signal: undefined });
    assert.equal(result.assertedIdentityClass, identityClass);
    assert.equal(result.valid, true);
    assert.equal(result.evidenceSource, `${identityClass}-evidence`);
    assert.equal(result.observedAt, raw(identityClass).observed_at);
  }
});

test("projection is exact, deterministic, immutable, and Limited/Full only", async () => {
  const result = await runSocialAuthorityComposition(options, dependencies(async () => response(raw("full"))));
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(Object.keys(result), ["schema", "version", "subject", "assertedIdentityClass", "valid", "diagnostic", "evidenceSource", "observedAt"]);
  assert.equal(result.schema, SOCIAL_AUTHORITY_PROJECTION_SCHEMA);
  assert.deepEqual(JSON.parse(formatSocialAuthorityResult(result).output), result);
  assert.equal(formatSocialAuthorityResult(result).exitCode, 0);
  assert.throws(() => { result.valid = false; }, TypeError);
  assert.doesNotMatch(JSON.stringify(result), /identity_class|current_full_relation|headers|transport/);
});

test("one real composed service load supplies the immutable snapshot projection", async () => {
  let observations = 0;
  let observed;
  const result = await runSocialAuthorityComposition(options, {
    ...dependencies(async () => response(raw("full"))),
    observeComposition(trace) {
      observations += 1;
      observed = trace;
      assert.equal(Object.isFrozen(trace), true);
      assert.equal(Object.isFrozen(trace.snapshot), true);
      assert.equal(trace.snapshot.statuses[subject], "full");
      assert.deepEqual(trace.snapshot.externalAssertions[subject], { subject, assertedStatus: "full", source: "hodlxxi-authority-probe", valid: true, evidenceRef: "full-evidence" });
    }
  });
  assert.equal(observations, 1);
  assert.equal(result.assertedIdentityClass, observed.snapshot.statuses[subject]);
  assert.equal(result.valid, observed.snapshot.externalAssertions[subject].valid);
  assert.equal(result.evidenceSource, observed.snapshot.externalAssertions[subject].evidenceRef);
});

test("exact-subject transport and explicit context expose only required reads", () => {
  const assertion = Object.freeze({ marker: true });
  const transport = createExactSubjectTransport(subject, assertion);
  assert.deepEqual(Object.keys(transport), ["readAssertion"]);
  assert.equal(transport.readAssertion(subject), assertion);
  assert.equal(transport.readAssertion("d".repeat(64)), undefined);
  const context = createExplicitSubjectContext(subject);
  assert.equal(context.getCurrentViewer(), subject);
  assert.deepEqual(context.listParticipants(), [{ id: subject, publicKey: subject, displayName: "Explicitly selected subject" }]);
  for (const method of ["listRelationships", "listFeed", "listGroups", "listConversations", "listNotifications"]) assert.deepEqual(context[method](), []);
  for (const operation of ["write", "publish", "readAssertion", "grantFull", "setStatus"]) assert.equal(context[operation], undefined);
  assert.equal(context.capabilities.length, 7);
});

test("invalid options cause zero reads and failures retain bounded V1.7 diagnostics", async () => {
  let reads = 0;
  await assert.rejects(runSocialAuthorityComposition({ ...options, subject: subject.toUpperCase() }, dependencies(async () => { reads += 1; })), (error) => error.diagnostic === "argument");
  assert.equal(reads, 0);
  for (const diagnostic of ["argument", "denied", "unavailable", "malformed", "invalid"]) {
    const formatted = formatSocialAuthorityFailure(new AuthorityProbeError(diagnostic, subject));
    const result = JSON.parse(formatted.output);
    assert.equal(formatted.exitCode, AUTHORITY_EXIT_CODES[diagnostic]);
    assert.notEqual(formatted.exitCode, 0);
    assert.deepEqual(result, { schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass: "limited", valid: false, diagnostic, evidenceSource: null, observedAt: null });
  }
  const hostile = formatSocialAuthorityFailure(new Error("remote secret\nstack operator full"));
  assert.doesNotMatch(hostile.output, /remote|secret|stack|operator/);
});

test("CLI parses once, composes once, and writes one deterministic record", async () => {
  let compositions = 0;
  const stdout = [];
  const stderr = [];
  const canonical = Object.freeze({ schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass: "limited", valid: true, diagnostic: "asserted", evidenceSource: "normalized", observedAt: null });
  const exitCode = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject, "--timeout-ms", "5000"], {
    async compose(checked) { compositions += 1; assert.deepEqual(checked, options); return canonical; },
    stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value)
  });
  assert.equal(compositions, 1);
  assert.equal(exitCode, 0);
  assert.deepEqual(stdout, [JSON.stringify(canonical)]);
  assert.deepEqual(stderr, []);
});

test("formatter accepts only exact canonical Limited and Full projections", async () => {
  for (const [assertedIdentityClass, observedAt] of [["limited", null], ["full", "2026-08-12T10:11:12+00:00"]]) {
    const canonical = Object.freeze({ schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass, valid: true, diagnostic: "asserted", evidenceSource: `${assertedIdentityClass}-evidence`, observedAt });
    const formatted = formatSocialAuthorityResult(canonical);
    assert.equal(formatted.exitCode, AUTHORITY_EXIT_CODES.asserted);
    assert.deepEqual(Object.keys(JSON.parse(formatted.output)), ["schema", "version", "subject", "assertedIdentityClass", "valid", "diagnostic", "evidenceSource", "observedAt"]);

    const stdout = [];
    const stderr = [];
    const exitCode = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject, "--timeout-ms", "5000"], {
      async compose() { return canonical; }, stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value)
    });
    assert.equal(exitCode, AUTHORITY_EXIT_CODES.asserted);
    assert.deepEqual(stdout, [formatted.output]);
    assert.deepEqual(stderr, []);
  }
});

test("formatter and injected CLI reject malformed projections without disclosure", async () => {
  const canonical = { schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass: "limited", valid: true, diagnostic: "asserted", evidenceSource: "safe-evidence", observedAt: null };
  let accessorReads = 0;
  const accessor = { ...canonical };
  Object.defineProperty(accessor, "evidenceSource", { enumerable: true, get() { accessorReads += 1; return "accessor-secret"; } });
  Object.freeze(accessor);
  const inherited = Object.create({ inheritedSecret: "prototype-secret" });
  Object.assign(inherited, canonical);
  Object.freeze(inherited);
  const malformed = [
    Object.freeze({ ...canonical, assertedIdentityClass: "operator" }),
    Object.freeze({ ...canonical, subject: subject.toUpperCase() }),
    Object.freeze({ ...canonical, subject: "abc" }),
    Object.freeze({ ...canonical, valid: false }),
    Object.freeze({ ...canonical, diagnostic: "remote-secret" }),
    Object.freeze({ ...canonical, evidenceSource: "hostile-secret\n\u001b[31m" }),
    Object.freeze({ ...canonical, observedAt: "not-a-timestamp" }),
    Object.freeze({ ...canonical, assertedIdentityClass: "full", observedAt: null }),
    Object.freeze(Object.fromEntries(Object.entries(canonical).filter(([field]) => field !== "evidenceSource"))),
    Object.freeze({ ...canonical, secretToken: "extra-secret" }),
    Object.freeze({ ...canonical, [Symbol("symbol-secret")]: "symbol-secret" }),
    accessor,
    inherited,
    { ...canonical }
  ];

  for (const candidate of malformed) {
    assert.throws(() => formatSocialAuthorityResult(candidate), TypeError);
    const stdout = [];
    const stderr = [];
    const exitCode = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject, "--timeout-ms", "5000"], {
      async compose() { return candidate; }, stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value)
    });
    assert.equal(exitCode, AUTHORITY_EXIT_CODES.malformed);
    assert.deepEqual(stdout, []);
    assert.equal(stderr.length, 1);
    assert.deepEqual(JSON.parse(stderr[0]), { schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject: "0".repeat(64), assertedIdentityClass: "limited", valid: false, diagnostic: "malformed", evidenceSource: null, observedAt: null });
    assert.doesNotMatch(stderr[0], /secret|hostile|operator|accessor|prototype|remote|stack|\u001b/i);
  }
  assert.equal(accessorReads, 0);
});

test("CLI failures preserve diagnostics, use stderr only, and sanitize hostile exceptions", async () => {
  for (const diagnostic of ["argument", "denied", "unavailable", "malformed", "invalid"]) {
    let compositions = 0;
    const stdout = [];
    const stderr = [];
    const exitCode = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject, "--timeout-ms", "5000"], {
      async compose() { compositions += 1; throw new AuthorityProbeError(diagnostic, subject); },
      stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value)
    });
    assert.equal(compositions, 1);
    assert.equal(exitCode, AUTHORITY_EXIT_CODES[diagnostic]);
    assert.deepEqual(stdout, []);
    assert.equal(stderr.length, 1);
    assert.equal(JSON.parse(stderr[0]).diagnostic, diagnostic);
    assert.equal(JSON.parse(stderr[0]).valid, false);
  }
  const stdout = [];
  const stderr = [];
  const exitCode = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject, "--timeout-ms", "5000"], {
    async compose() { throw new Error("hostile remote secret\nstack full operator"); },
    stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value)
  });
  assert.equal(exitCode, AUTHORITY_EXIT_CODES.malformed);
  assert.deepEqual(stdout, []);
  assert.equal(stderr.length, 1);
  assert.doesNotMatch(stderr[0], /hostile|remote|secret|stack|operator/);

  let invalidCompositions = 0;
  const invalidStderr = [];
  const invalidExit = await runSocialAuthorityCli(["--origin", options.origin, "--subject", subject.toUpperCase(), "--timeout-ms", "5000"], {
    async compose() { invalidCompositions += 1; }, stdout() {}, stderr: (value) => invalidStderr.push(value)
  });
  assert.equal(invalidCompositions, 0);
  assert.equal(invalidExit, AUTHORITY_EXIT_CODES.argument);
  assert.equal(JSON.parse(invalidStderr[0]).diagnostic, "argument");
});

test("denied, unavailable, malformed, mismatch, and Operator cannot reflect Full", async () => {
  for (const [body, status, diagnostic] of [
    [{ error: "entitlement_denied" }, 404, "denied"],
    [{ error: "entitlement_unavailable" }, 503, "unavailable"],
    [{ nope: true }, 200, "malformed"],
    [raw("full", { subject: "d".repeat(64) }), 200, "malformed"],
    [raw("operator", { current_full_relation_satisfied: false, observed_at: null }), 200, "malformed"]
  ]) await assert.rejects(runSocialAuthorityComposition(options, dependencies(async () => response(body, status))), (error) => error.diagnostic === diagnostic);
  const absent = formatSocialAuthorityFailure(new Error("absent"));
  assert.equal(JSON.parse(absent.output).assertedIdentityClass, "limited");
  assert.equal(JSON.parse(absent.output).valid, false);
});

test("implementation reuses V1.7 and contains no alternate authority or side-effect path", async () => {
  const implementation = await readFile(new URL("../src/dev/hodlxxi-authority-live-composition.mjs", import.meta.url), "utf8");
  const cli = await readFile(new URL("../scripts/hodlxxi-authority-social-probe.mjs", import.meta.url), "utf8");
  assert.match(implementation, /parseAuthorityProbeArgs/);
  assert.match(implementation, /runAuthorityProbe/);
  assert.match(implementation, /snapshot\.statuses\[checked\.subject\]/);
  assert.match(implementation, /snapshot\.externalAssertions\[checked\.subject\]/);
  assert.doesNotMatch(implementation, /createServiceImpl|dependencies\.createService|dependencies\[.*createService/);
  assert.doesNotMatch(implementation + cli, /SyntheticSocialAdapter|process\.env|localStorage|sessionStorage|indexedDB|WebSocket|setInterval|Authorization|private.?key|\b(?:POST|PUT|PATCH|DELETE)\b|grantFull|issueCRT|setStatus|bitcoin|lightning|sign\w*\(|publish\w*\(|deploy/i);
  assert.doesNotMatch(implementation, /identity_class|current_full_relation_satisfied/);
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
});

test("protected browser, Nostr, package, and core boundaries match audited content and remain isolated", async () => {
  for (const [path, expectedSha256] of Object.entries(protectedContentSha256)) {
    const current = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
    assert.equal(contentSha256(current), expectedSha256, `${path} must match the audited protected content`);
    assert.doesNotMatch(current, /hodlxxi-authority-live-composition|hodlxxi-authority-social-probe/);
  }
});

test("explicit ordinary bootstrap preserves V1.8 isolation and developer imports remain inert", async () => {
  const app = await readFile(new URL("../web/app.mjs", import.meta.url), "utf8");
  const index = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  const developer = await readFile(new URL("../web/dev-participant-shell.mjs", import.meta.url), "utf8");
  assert.match(index, /data-hodlxxi-synthetic-app/);
  assert.equal((index.match(/src="\.\/app\.mjs"/g) ?? []).length, 1);
  assert.match(app, /export function bootstrapSyntheticApp/);
  assert.match(app, /let fixtureData;\s*function getFixtureData\(\)/);
  assert.doesNotMatch(app.slice(0, app.indexOf("function getFixtureData")), /\.load\(\)/);
  assert.match(app, /hasAttribute\?\.\("data-hodlxxi-synthetic-app"\)/);
  assert.equal((app.match(/bootstrapSyntheticApp\(document\)/g) ?? []).length, 1);
  assert.doesNotMatch(app, /hodlxxi-participant-live-composition|WebSocketNostrReadTransport|fetch\s*\(/);
  assert.match(developer, /loadParticipantLive/);
  assert.match(developer, /if \(typeof document !== "undefined"\) bindParticipantShell\(document\)/);
  assert.doesNotMatch(developer, /SyntheticSocialAdapter|renderApp\(|bootstrapSyntheticApp\(|setInterval|setTimeout|localStorage|sessionStorage|indexedDB/);
});
