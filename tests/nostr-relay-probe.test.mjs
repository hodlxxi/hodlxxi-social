import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  EXIT_CODES, PROBE_LIMITS, ProbeError, formatProbeFailure, formatProbeResult, parseProbeArgs, runProbe
} from "../src/dev/nostr-relay-probe.mjs";

const ada = "a".repeat(64);
const signed = (overrides = {}) => ({
  id: "e".repeat(64), pubkey: ada, created_at: 1, kind: 1, tags: [], content: "hello", sig: "f".repeat(128), ...overrides
});
const args = (overrides = []) => parseProbeArgs(["--relay", "wss://relay.test", "--kind", "1", ...overrides]);

function fakeRun(events, options = args()) {
  const calls = [];
  const dependencies = {
    now: (() => { const values = [100, 125]; return () => values.shift(); })(),
    transportFactory(configuration) {
      calls.push(["construct", configuration]);
      return { relayUrl: "wss://relay.test/", async read(filter) { calls.push(["read", filter]); return events; } };
    }
  };
  return { calls, result: runProbe(options, dependencies) };
}

test("arguments require an explicit relay and supported explicit kind", () => {
  assert.throws(() => parseProbeArgs([]), /--relay is required/);
  assert.throws(() => parseProbeArgs(["--relay", "wss://relay.test"]), /--kind is required/);
  for (const kind of ["2", "4", "-1", "text"]) assert.throws(() => parseProbeArgs(["--relay", "wss://relay.test", "--kind", kind]), /--kind/);
  assert.equal(args().kind, 1);
  assert.equal(parseProbeArgs(["--relay", "wss://relay.test", "--kind", "0"]).kind, 0);
});

test("unknown, duplicate, and secret or write-shaped options fail closed", () => {
  for (const extra of [["--relay", "wss://other.test"], ["--json", "--json"], ["--nsec", "secret"], ["--private-key", "secret"], ["--sign"], ["--publish"], ["--auth"], ["--dm"], ["--crt", "x"]]) {
    assert.throws(() => args(extra), /duplicate|unsupported/);
  }
  assert.throws(() => args(["--author"]), /requires a value/);
});

test("author, limit, and timeout are canonical and strictly bounded", () => {
  const parsed = args(["--author", ada.toUpperCase(), "--limit", "10", "--timeout-ms", "250", "--json"]);
  assert.equal(parsed.author, ada);
  assert.equal(parsed.limit, 10);
  assert.equal(parsed.timeoutMs, 250);
  assert.equal(parsed.json, true);
  for (const author of ["a", "z".repeat(64), `${ada}00`]) assert.throws(() => args(["--author", author]), /--author/);
  for (const limit of ["0", "11", "1.5", "-1"]) assert.throws(() => args(["--limit", limit]), /--limit/);
  for (const timeout of ["249", "30001", "1.5", "-1"]) assert.throws(() => args(["--timeout-ms", timeout]), /--timeout-ms/);
  assert.equal(args().limit, PROBE_LIMITS.defaultLimit);
  assert.equal(args().timeoutMs, PROBE_LIMITS.defaultTimeoutMs);
});

test("relay validation is delegated to V1.4 before any read", async () => {
  for (const relay of ["not-a-url", "https://relay.test", "ws://relay.test", "wss://user@relay.test", "wss://relay.test/#x"]) {
    const options = parseProbeArgs(["--relay", relay, "--kind", "1"]);
    await assert.rejects(runProbe(options), (error) => error.category === "argument");
  }
});

test("one adapter read forwards the exact narrow bounded filter", async () => {
  const options = args(["--author", ada, "--limit", "2", "--timeout-ms", "1000"]);
  const state = fakeRun([signed()], options);
  const result = await state.result;
  assert.deepEqual(state.calls, [
    ["construct", { relayUrl: "wss://relay.test", openTimeoutMs: 1000, readTimeoutMs: 1000, maxEvents: 2 }],
    ["read", { kinds: [1], authors: [ada], limit: 2 }]
  ]);
  assert.equal(result.rawEventsReceived, 1);
  assert.equal(result.acceptedEvents, 1);
  assert.equal(result.elapsedMs, 25);
});

test("canonical adapter produces bounded sanitized note output", async () => {
  const raw = signed({ content: `hello\n${"x".repeat(300)}`, tags: [["unknown", "do-not-print"]], relaySecret: undefined });
  delete raw.relaySecret;
  const result = await fakeRun([raw]).result;
  assert.equal(result.records.length, 1);
  assert.deepEqual(Object.keys(result.records[0]), ["type", "id", "author", "kind", "created_at", "preview"]);
  assert.equal(result.records[0].preview.length, PROBE_LIMITS.previewCharacters);
  const human = formatProbeResult(result);
  const json = formatProbeResult(result, { json: true });
  for (const output of [human, json]) {
    assert.doesNotMatch(output, /do-not-print|unknown|sig|tags|raw payload/);
    assert.match(output, /completed/);
  }
});

test("canonical profile output is normalized and minimized", async () => {
  const profile = signed({ kind: 0, content: JSON.stringify({ display_name: "Ada", about: "not emitted", status: "operator" }) });
  const result = await fakeRun([profile], parseProbeArgs(["--relay", "wss://relay.test", "--kind", "0"])).result;
  assert.deepEqual(result.records, [{ type: "profile", author: ada, preview: "Ada" }]);
  assert.doesNotMatch(formatProbeResult(result, { json: true }), /about|operator/);
});

test("zero events are a successful deterministic result", async () => {
  const result = await fakeRun([]).result;
  assert.equal(result.completionReason, "zero-events");
  assert.equal(result.rawEventsReceived, 0);
  assert.equal(result.acceptedEvents, 0);
  assert.deepEqual(result.records, []);
});

test("transport, timeout, malformed result, and canonical rejection are classified", async () => {
  const failure = async (error) => runProbe(args(), { transportFactory: () => ({ relayUrl: "wss://relay.test/", read: async () => { throw error; } }) });
  await assert.rejects(failure(new Error("connection failed")), (error) => error.category === "transport");
  await assert.rejects(failure(new Error("Nostr relay read timed out")), (error) => error.category === "timeout");
  await assert.rejects(runProbe(args(), { transportFactory: () => ({ read: async () => ({ raw: true }) }) }), (error) => error.category === "malformed");
  await assert.rejects(fakeRun([signed({ privateField: "rejected" })]).result, (error) => error.category === "validation");
  assert.equal(formatProbeFailure(new ProbeError("timeout", "timed out")).exitCode, EXIT_CODES.timeout);
});

test("normalization exceptions are canonical validation failures", async () => {
  const outOfRange = signed({ created_at: Number.MAX_SAFE_INTEGER });
  await assert.rejects(fakeRun([outOfRange]).result, (error) => error.category === "validation");
  const failure = formatProbeFailure(new ProbeError("validation", "public event normalization failed"));
  assert.equal(failure.exitCode, EXIT_CODES.validation);
});

test("relay events must match the exact requested kind and author", async () => {
  await assert.rejects(fakeRun([signed({ kind: 0 })]).result, (error) => error.category === "validation");
  const scoped = args(["--author", ada]);
  await assert.rejects(fakeRun([signed({ pubkey: "b".repeat(64) })], scoped).result, (error) => error.category === "validation");
  const uppercase = await fakeRun([signed({ pubkey: ada.toUpperCase() })], scoped).result;
  assert.equal(uppercase.acceptedEvents, 1);
});

test("failure output never includes relay-controlled exception text", () => {
  const relayText = `NOTICE-${"x".repeat(10_000)}`;
  for (const json of [false, true]) {
    const failure = formatProbeFailure(new Error(`Nostr relay notice: ${relayText}`), { json });
    assert.equal(failure.exitCode, EXIT_CODES.transport);
    assert.doesNotMatch(failure.output, /NOTICE-|x{20}/);
    assert.ok(failure.output.length < 100);
  }
});

test("adapter remains the validation boundary and unexpected orchestration fails", async () => {
  let adapterCalls = 0;
  await assert.rejects(runProbe(args(), {
    transportFactory: () => ({ read: async () => [signed()] }),
    adapterFactory: async ({ transport }) => { adapterCalls += 1; await transport.read({ kinds: [1] }); return {}; }
  }), (error) => error.category === "validation");
  assert.equal(adapterCalls, 1);
});

test("probe stays developer-only, read-only, offline-testable, and authority-free", async () => {
  const [core, cli, app] = await Promise.all([
    readFile(new URL("../src/dev/nostr-relay-probe.mjs", import.meta.url), "utf8"),
    readFile(new URL("../scripts/nostr-relay-probe.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/app.mjs", import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(core + cli, /localStorage|sessionStorage|indexedDB|process\.env|HodlxxiAuthorityReadAdapter|readAssertion|grantFull|grantOperator|issueCRT|\.publish\(|\bsign\w*\(|nsec|seed|NIP-07|NIP-44|NIP-59/i);
  assert.match(app, /new SyntheticSocialAdapter/);
  assert.doesNotMatch(app, /nostr-relay-probe|WebSocketNostrReadTransport|relay selector|live Nostr/i);
});
