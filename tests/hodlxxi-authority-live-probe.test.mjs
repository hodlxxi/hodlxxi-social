import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AccessStatus } from "../src/domain.mjs";
import { keys } from "../src/fixtures.mjs";
import { HodlxxiAuthorityReadAdapter } from "../src/data/hodlxxi-authority-read-adapter.mjs";
import { NostrPublicReadAdapter } from "../src/data/nostr-public-read-adapter.mjs";
import { createComposedSocialDataService } from "../src/data/composition.mjs";
import { SyntheticSocialAdapter } from "../src/data/synthetic-adapter.mjs";
import { AUTHORITY_EXIT_CODES, AuthorityProbeError, formatAuthorityFailure, formatAuthorityResult, parseAuthorityProbeArgs, runAuthorityProbe, validateAuthorityOrigin } from "../src/dev/hodlxxi-authority-live-probe.mjs";

const subject = keys.cy;
const options = (overrides = {}) => ({ origin: "https://authority.example", subject, timeoutMs: 5000, ...overrides });
const assertion = (overrides = {}) => ({ schema: "hodlxxi.current_entitlement_assertion.v1", subject, valid: true, identity_class: "limited", current_full_relation_satisfied: false, evidence_source: "baseline", observed_at: null, ...overrides });
const response = (body, { status = 200, contentType = "application/json", contentLength } = {}) => {
  const bytes = body instanceof Uint8Array ? body : new TextEncoder().encode(typeof body === "string" ? body : JSON.stringify(body));
  const headers = new Headers(contentType === null ? {} : { "content-type": contentType });
  if (contentLength !== undefined) headers.set("content-length", contentLength);
  return { status, headers, body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }) };
};
const dependencies = (fetchImpl, counters = { timers: 0, clears: 0 }) => ({ fetchImpl, setTimeoutImpl(fn, ms) { counters.timers += 1; return { fn, ms }; }, clearTimeoutImpl() { counters.clears += 1; } });

test("raw origin must already equal canonical URL.origin", () => {
  for (const origin of ["https://authority.example", "https://authority.example:8443", "https://[2001:db8::1]"]) assert.equal(validateAuthorityOrigin(origin), origin);
  for (const origin of ["https://authority.example?", "https://authority.example#", "https://@authority.example", "https://user@authority.example", "https://user:@authority.example", "https://authority.example/", "https://authority.example/.", "https://authority.example/%2e", "https://authority.example/path", "https://authority.example?x=1", "https://authority.example#fragment", "https://authority.example:443", "HTTPS://authority.example", "https://AUTHORITY.example", " https://authority.example", "https://authority.example ", "http://authority.example", "not a URL", ""]) assert.throws(() => validateAuthorityOrigin(origin), (error) => error instanceof AuthorityProbeError && error.diagnostic === "argument");
});

test("CLI and direct invalid options create zero reads and zero timers", async () => {
  for (const origin of ["https://authority.example?", "https://authority.example#", "https://@authority.example", "https://user@authority.example", "https://user:@authority.example", "https://authority.example/", "https://authority.example/.", "https://authority.example/%2e", "https://authority.example/path", "https://authority.example?x=1", "https://authority.example#fragment", "https://authority.example:443", "HTTPS://authority.example", "https://AUTHORITY.example", " https://authority.example", "https://authority.example ", "http://authority.example", "not a URL"]) assert.throws(() => parseAuthorityProbeArgs(["--origin", origin, "--subject", subject, "--timeout-ms", "5000"]), /argument/);
  for (const argv of [[], ["--origin", "https://authority.example"], ["--unknown", "x"], ["--origin", "https://authority.example", "--origin", "https://authority.example", "--subject", subject, "--timeout-ms", "5000"]]) assert.throws(() => parseAuthorityProbeArgs(argv), /argument/);
  const symbolOption = options(); symbolOption[Symbol("extra")] = true;
  for (const candidate of [null, [], {}, options({ extra: true }), symbolOption, options({ subject: subject.toUpperCase() }), options({ timeoutMs: 249 }), options({ timeoutMs: 30001 }), Object.assign(Object.create({}), options())]) {
    let reads = 0; const counters = { timers: 0, clears: 0 };
    await assert.rejects(runAuthorityProbe(candidate, dependencies(async () => { reads += 1; }, counters)), (error) => error.diagnostic === "argument");
    assert.deepEqual({ reads, timers: counters.timers }, { reads: 0, timers: 0 });
  }
});

test("one exact credential-free bounded GET returns canonical Limited", async () => {
  const calls = []; const counters = { timers: 0, clears: 0 };
  const result = await runAuthorityProbe(options(), dependencies(async (...args) => { calls.push(args); return response(assertion(), { contentType: "application/json; charset=utf-8" }); }, counters));
  assert.equal(calls.length, 1); assert.equal(calls[0][0], `https://authority.example/agent/authority/current/${subject}.json`);
  assert.deepEqual({ ...calls[0][1], signal: undefined }, { method: "GET", redirect: "manual", credentials: "omit", headers: { Accept: "application/json" }, signal: undefined });
  assert.equal(calls[0][1].body, undefined); assert.deepEqual(counters, { timers: 1, clears: 1 }); assert.equal(result.status, AccessStatus.LIMITED);
  assert.deepEqual(Object.keys(result), ["source", "schema", "version", "subject", "status", "valid", "diagnostic", "evidenceSource", "observedAt"]);
  assert.equal(formatAuthorityResult(result).exitCode, 0);
});

test("content type accepts valid parameters and rejects malformed syntax", async () => {
  for (const contentType of ["application/json;charset=utf-8", "application/json; charset=\"utf-8\"; profile=current"]) assert.equal((await runAuthorityProbe(options(), dependencies(async () => response(assertion(), { contentType })))).valid, true);
  for (const contentType of ["application/json;", "application/json; garbage", "application/json; charset=", "application/json; =utf-8", "application/json; charset=\"unterminated"]) await assert.rejects(runAuthorityProbe(options(), dependencies(async () => response(assertion(), { contentType }))), (error) => error.diagnostic === "malformed");
});

test("exact success contract accepts canonical Limited and Full timestamps", async () => {
  for (const raw of [assertion(), assertion({ evidence_source: "evidence", observed_at: "2026-08-12T10:11:12+00:00" }), assertion({ identity_class: "full", current_full_relation_satisfied: true, evidence_source: "full", observed_at: "2026-08-12T10:11:12.123456+00:00" })]) {
    const result = await runAuthorityProbe(options(), dependencies(async () => response(raw))); assert.equal(result.status, raw.identity_class); assert.equal(result.valid, true);
  }
});

test("contract rejects timestamps, evidence injection, obsolete fields, and contradictions", async () => {
  const bad = [assertion({ observed_at: "2026-08-12T10:11:12Z" }), assertion({ observed_at: "2026-08-12T10:11:12.1+00:00" }), assertion({ observed_at: "2026-08-12t10:11:12+00:00" }), assertion({ observed_at: "2026-02-30T10:11:12+00:00" }), assertion({ observed_at: "2026-08-12T10:11:12+01:00" }), assertion({ evidence_source: " padded " }), assertion({ evidence_source: "x".repeat(129) }), assertion({ evidence_source: "bad\u001b[31m" }), assertion({ evidence_source: "bad\u202e" }), assertion({ identity_class: "operator" }), assertion({ identity_class: "full", current_full_relation_satisfied: false, observed_at: "2026-08-12T10:11:12+00:00" }), assertion({ access_level: "full" }), { ...assertion(), entitled: true }, { ...assertion(), evidence_id: "x" }, { ...assertion(), subject: keys.ada }, { ...assertion(), valid: false }];
  assert.equal((await runAuthorityProbe(options(), dependencies(async () => response(assertion({ evidence_source: "😀".repeat(128) }))))).valid, true);
  for (const raw of bad) await assert.rejects(runAuthorityProbe(options(), dependencies(async () => response(raw))), (error) => error.diagnostic === "malformed");
});

test("exact error shapes and transport failures retain closed classifications", async () => {
  for (const [status, body, diagnostic] of [[404, { error: "entitlement_denied" }, "denied"], [503, { error: "entitlement_unavailable" }, "unavailable"], [400, { error: "invalid_subject" }, "invalid"]]) await assert.rejects(runAuthorityProbe(options(), dependencies(async () => response(body, { status }))), (error) => error.diagnostic === diagnostic && error.assertion.status === "limited" && !error.assertion.valid);
  for (const failure of [new Error("remote secret"), Object.assign(new Error("aborted"), { name: "AbortError" })]) await assert.rejects(runAuthorityProbe(options(), dependencies(async () => { throw failure; })), (error) => error.diagnostic === "unavailable" && !error.message.includes("secret"));
  await assert.rejects(runAuthorityProbe(options(), { fetchImpl: null }), (error) => error.diagnostic === "argument");
});

test("bounded timer abort is unavailable", async () => {
  let timerCallback;
  const deps = {
    fetchImpl: (_url, { signal }) => new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(Object.assign(new Error("stopped"), { name: "AbortError" })))),
    setTimeoutImpl(callback) { timerCallback = callback; return 1; }, clearTimeoutImpl() {}
  };
  const pending = runAuthorityProbe(options(), deps);
  timerCallback();
  await assert.rejects(pending, (error) => error.diagnostic === "unavailable");
});

test("malformed transport responses fail closed", async () => {
  for (const item of [response(assertion(), { status: 302 }), response(assertion(), { contentType: "text/plain" }), response(assertion(), { contentLength: "32769" }), response(assertion(), { contentLength: "invalid" }), response(new Uint8Array([0xc3, 0x28])), response(new Uint8Array(32769)), response("not-json")]) await assert.rejects(runAuthorityProbe(options(), dependencies(async () => item)), (error) => error.diagnostic === "malformed");
});

test("pre-body malformed response cancels a supported body", async () => {
  let cancelled = 0;
  const malformed = { status: "200", headers: new Headers({ "content-type": "application/json" }), body: { async cancel() { cancelled += 1; } } };
  await assert.rejects(runAuthorityProbe(options(), dependencies(async () => malformed)), (error) => error.diagnostic === "malformed");
  assert.equal(cancelled, 1);
});

test("authoritative exit mapping never makes an exception asserted or successful", () => {
  assert.deepEqual(AUTHORITY_EXIT_CODES, { asserted: 0, argument: 2, denied: 3, unavailable: 4, malformed: 5, invalid: 6 });
  for (const diagnostic of ["argument", "denied", "unavailable", "malformed", "invalid"]) { const formatted = formatAuthorityFailure(new AuthorityProbeError(diagnostic, subject)); assert.equal(formatted.exitCode, AUTHORITY_EXIT_CODES[diagnostic]); assert.notEqual(formatted.exitCode, 0); }
  assert.equal(formatAuthorityFailure(new Error("remote body")).exitCode, 5);
  for (const forged of [{ valid: true, diagnostic: "asserted" }, { ...assertion(), source: "hodlxxi-authority-probe", status: "full", diagnostic: "asserted" }]) assert.throws(() => formatAuthorityResult(forged), /canonical/);
});

test("unchanged adapter and composition project only canonical Limited or Full", async () => {
  for (const raw of [assertion(), assertion({ identity_class: "full", current_full_relation_satisfied: true, observed_at: "2026-08-12T10:11:12+00:00" })]) {
    const canonical = await runAuthorityProbe(options(), dependencies(async () => response(raw)));
    const data = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(subject), authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: (id) => id === subject ? canonical : undefined }) }).load();
    assert.equal(data.statuses[subject], raw.identity_class); assert.notEqual(data.statuses[subject], AccessStatus.OPERATOR);
  }
  const malformed = { source: "hodlxxi-authority-probe", schema: "hodlxxi.current_entitlement_assertion.v1", version: 1, subject, status: "operator", valid: true, diagnostic: "asserted", evidenceSource: "x", observedAt: null };
  const data = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(subject), authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => malformed }) }).load(); assert.equal(data.statuses[subject], AccessStatus.LIMITED);
});

test("failures and social inputs cannot elevate through composition", async () => {
  for (const diagnostic of ["denied", "unavailable", "malformed", "invalid"]) {
    const failed = new AuthorityProbeError(diagnostic, subject).assertion;
    const data = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(subject), authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => failed }) }).load();
    assert.equal(data.statuses[subject], AccessStatus.LIMITED);
    assert.equal(data.friendEdges.length > 0, true);
    assert.equal(data.sponsorTrustEdges.length > 0, true);
  }
  const event = { id: "e".repeat(64), pubkey: subject, created_at: 1, kind: 0, tags: [], content: JSON.stringify({ display_name: "Cy", status: "operator", source: "hodlxxi-authority-probe" }), sig: "f".repeat(128) };
  const nostr = await NostrPublicReadAdapter.create({ viewerId: subject, transport: { read: () => [event] } });
  const full = await runAuthorityProbe(options(), dependencies(async () => response(assertion({ identity_class: "full", current_full_relation_satisfied: true, observed_at: "2026-08-12T10:11:12+00:00" }))));
  for (const socialAdapter of [nostr, new SyntheticSocialAdapter(subject)]) {
    const closed = createComposedSocialDataService({ authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => undefined }), socialAdapter }).load();
    assert.equal(closed.statuses[subject], AccessStatus.LIMITED);
    const authoritative = createComposedSocialDataService({ authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => full }), socialAdapter }).load();
    assert.equal(authoritative.statuses[subject], AccessStatus.FULL);
    assert.notEqual(authoritative.statuses[subject], AccessStatus.OPERATOR);
    const reordered = createComposedSocialDataService({ socialAdapter, now: 100, authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => full }) }).load();
    assert.equal(reordered.statuses[subject], AccessStatus.FULL);
  }
});

test("accessor-backed canonical records fail closed without executing accessors", () => {
  let reads = 0;
  const raw = {};
  for (const field of ["source", "schema", "version", "subject", "status", "valid", "diagnostic", "evidenceSource", "observedAt"]) Object.defineProperty(raw, field, { enumerable: true, get() { reads += 1; throw new Error("accessor executed"); } });
  const data = createComposedSocialDataService({ socialAdapter: new SyntheticSocialAdapter(subject), authorityAdapter: new HodlxxiAuthorityReadAdapter({ readAssertion: () => raw }) }).load();
  assert.equal(reads, 0);
  assert.equal(data.statuses[subject], AccessStatus.LIMITED);
});

test("probe remains isolated and contains no mutation or secret path", async () => {
  const files = await Promise.all(["../src/dev/hodlxxi-authority-live-probe.mjs", "../scripts/hodlxxi-authority-probe.mjs", "../web/index.html", "../web/app.mjs", "../web/dev-live.mjs", "../src/dev/live-social-composition.mjs", "../scripts/nostr-relay-probe.mjs"].map((path) => readFile(new URL(path, import.meta.url), "utf8")));
  for (const source of files.slice(2)) assert.doesNotMatch(source, /hodlxxi-authority-(?:live-)?probe/);
  assert.doesNotMatch(files[0] + files[1], /process\.env|localStorage|sessionStorage|indexedDB|private.?key|\b(?:POST|PUT|PATCH|DELETE)\b|sign\w*\(|publish\w*\(|grant|issueCRT|bitcoin|lightning|LND|custody|setInterval/i);
});
