import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AuthorityProbeError } from "../src/dev/hodlxxi-authority-live-probe.mjs";
import { SOCIAL_AUTHORITY_PROJECTION_SCHEMA } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { bindDevAuthorityPage } from "../web/dev-authority.mjs";

const subject = "a".repeat(64);
const options = { origin: "https://authority.example", subject, timeoutMs: 5000 };
const projection = (overrides = {}) => Object.freeze({
  schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA,
  version: 1,
  subject,
  assertedIdentityClass: "limited",
  valid: true,
  diagnostic: "asserted",
  evidenceSource: "safe-evidence",
  observedAt: null,
  ...overrides
});

class Element {
  constructor() { this.listeners = new Map(); this.value = ""; this.disabled = false; this.button = undefined; this.writes = []; this._textContent = ""; }
  set textContent(value) { this.writes.push(value); this._textContent = value; }
  get textContent() { return this._textContent; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  querySelector(selector) { return selector === 'button[type="submit"]' ? this.button : undefined; }
}

function fakeDocument() {
  const ids = [
    "#dev-authority-form", "#authority-origin", "#authority-subject", "#authority-timeout",
    "#authority-selected-subject", "#authority-class", "#authority-validity",
    "#authority-diagnostic", "#authority-evidence", "#authority-observed-at"
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  elements["#dev-authority-form"].button = new Element();
  elements["#authority-origin"].value = options.origin;
  elements["#authority-subject"].value = options.subject;
  elements["#authority-timeout"].value = String(options.timeoutMs);
  return { elements, querySelector: (selector) => elements[selector] };
}

const submit = (binding) => binding.form.listeners.get("submit")({ preventDefault() {} });
const field = (document, id) => document.elements[id].textContent;
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

test("binding starts idle with zero composition calls and invalid input is never selected", async () => {
  const document = fakeDocument();
  let calls = 0;
  const binding = bindDevAuthorityPage(document, { compose: async () => { calls += 1; return projection(); } });
  assert.equal(calls, 0);
  document.elements["#authority-subject"].value = subject.toUpperCase();
  await submit(binding);
  assert.equal(calls, 0);
  assert.equal(field(document, "#authority-selected-subject"), "None");
  assert.equal(field(document, "#authority-class"), "Limited");
  assert.equal(field(document, "#authority-validity"), "Fail-closed");
  assert.equal(field(document, "#authority-diagnostic"), "argument");
});

test("one accepted submit shows validated subject while loading and asserted Full", async () => {
  const document = fakeDocument();
  const pending = deferred();
  const calls = [];
  const binding = bindDevAuthorityPage(document, { compose: (value) => { calls.push(value); return pending.promise; } });
  const completion = submit(binding);
  assert.deepEqual(calls, [options]);
  assert.equal(field(document, "#authority-selected-subject"), subject);
  assert.equal(field(document, "#authority-validity"), "Loading");
  assert.equal(binding.form.button.disabled, true);
  pending.resolve(projection({ assertedIdentityClass: "full", observedAt: "2026-08-12T10:11:12+00:00" }));
  await completion;
  assert.equal(field(document, "#authority-selected-subject"), subject);
  assert.equal(field(document, "#authority-class"), "Full");
  assert.equal(field(document, "#authority-validity"), "Valid external assertion");
  assert.equal(field(document, "#authority-diagnostic"), "asserted");
  assert.equal(field(document, "#authority-evidence"), "safe-evidence");
  assert.equal(field(document, "#authority-observed-at"), "2026-08-12T10:11:12+00:00");
  assert.equal(binding.form.button.disabled, false);
});

test("asserted Limited is valid and authority failures preserve the validated subject", async () => {
  const limitedDocument = fakeDocument();
  const limited = bindDevAuthorityPage(limitedDocument, { compose: async () => projection() });
  await submit(limited);
  assert.equal(field(limitedDocument, "#authority-class"), "Limited");
  assert.equal(field(limitedDocument, "#authority-validity"), "Valid external assertion");

  for (const diagnostic of ["unavailable", "denied"]) {
    const document = fakeDocument();
    const binding = bindDevAuthorityPage(document, { compose: async () => { throw new AuthorityProbeError(diagnostic, subject); } });
    await submit(binding);
    assert.equal(field(document, "#authority-selected-subject"), subject);
    assert.equal(field(document, "#authority-class"), "Limited");
    assert.equal(field(document, "#authority-validity"), "Fail-closed");
    assert.equal(field(document, "#authority-diagnostic"), diagnostic);
    assert.equal(binding.form.button.disabled, false);
  }
});

test("malformed projections and actual Operator class fail closed without arbitrary errors", async () => {
  for (const value of [
    { arbitrary: true },
    projection({ assertedIdentityClass: "operator" })
  ]) {
    const document = fakeDocument();
    const binding = bindDevAuthorityPage(document, { compose: async () => value });
    await submit(binding);
    assert.equal(field(document, "#authority-selected-subject"), subject);
    assert.equal(field(document, "#authority-class"), "Limited");
    assert.equal(field(document, "#authority-diagnostic"), "malformed");
    assert.doesNotMatch(Object.values(document.elements).map((element) => element.textContent).join(" "), /operator|arbitrary/i);
  }

  const document = fakeDocument();
  const secret = "credential response body stack transport detail";
  const binding = bindDevAuthorityPage(document, { compose: async () => { throw new Error(secret); } });
  await submit(binding);
  assert.equal(field(document, "#authority-diagnostic"), "malformed");
  assert.doesNotMatch(Object.values(document.elements).map((element) => element.textContent).join(" "), new RegExp(secret));
});

test("operator substrings suppress only evidence and retain formatter-valid class", async () => {
  for (const evidenceSource of ["operator", "Operator", "OPERATOR", "Operatorish", "xOperatory"]) {
    const document = fakeDocument();
    const result = projection({ assertedIdentityClass: "full", evidenceSource, observedAt: "2026-08-12T10:11:12+00:00" });
    const binding = bindDevAuthorityPage(document, { compose: async () => result });
    await submit(binding);
    assert.equal(field(document, "#authority-class"), "Full");
    assert.equal(field(document, "#authority-validity"), "Valid external assertion");
    assert.equal(field(document, "#authority-evidence"), "Suppressed");
  }
});

test("concurrent submissions are excluded, controls restore, and later submission runs once", async () => {
  const document = fakeDocument();
  const first = deferred();
  let calls = 0;
  const binding = bindDevAuthorityPage(document, { compose: async () => { calls += 1; return calls === 1 ? first.promise : projection(); } });
  const completion = submit(binding);
  await submit(binding);
  assert.equal(calls, 1);
  first.reject(new AuthorityProbeError("unavailable", subject));
  await completion;
  assert.equal(binding.form.button.disabled, false);
  await submit(binding);
  assert.equal(calls, 2);
  assert.equal(field(document, "#authority-validity"), "Valid external assertion");
});

test("HTML declares exact bounds, labels, non-claims, links, and text-only result fields", async () => {
  const html = await readFile(new URL("../web/dev-authority.html", import.meta.url), "utf8");
  assert.match(html, /DEV \/ LIVE HODLXXI AUTHORITY/);
  assert.match(html, /EXPLICIT SUBJECT \/ NOT AUTHENTICATED/);
  assert.match(html, /ONE-SHOT \/ NO PERSISTENCE/);
  assert.match(html, /id="authority-timeout"[^>]*min="250"[^>]*max="30000"/);
  assert.match(html, /href="\.\/index\.html"/);
  assert.match(html, /href="\.\/dev-live\.html"/);
  assert.match(html, /does not authenticate.*issue status.*prove possession of a private key.*persist results.*production mode/i);
  assert.doesNotMatch(html, /type=["'](?:password|hidden)["']|value="https:\/\//i);

  const document = fakeDocument();
  const hostile = "<img src=x onerror=alert(1)>";
  const binding = bindDevAuthorityPage(document, { compose: async () => projection({ evidenceSource: hostile }) });
  await submit(binding);
  assert.equal(field(document, "#authority-evidence"), hostile);
  assert.equal(document.elements["#authority-evidence"].writes.at(-1), hostile);
});

test("authority page remains isolated and contains no persistence or automatic behavior", async () => {
  const [module, html, index, app, nostrHtml, nostrModule] = await Promise.all([
    readFile(new URL("../web/dev-authority.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-authority.html", import.meta.url), "utf8"),
    readFile(new URL("../web/index.html", import.meta.url), "utf8"),
    readFile(new URL("../web/app.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.html", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.mjs", import.meta.url), "utf8")
  ]);
  assert.match(module, /parseAuthorityProbeArgs/);
  assert.match(module, /runSocialAuthorityComposition/);
  assert.match(module, /formatSocialAuthorityResult/);
  assert.doesNotMatch(index + app + nostrHtml + nostrModule, /dev-authority/);
  assert.doesNotMatch(module + html, /localStorage|sessionStorage|indexedDB|document\.cookie|serviceWorker|setInterval|setTimeout|requestAnimationFrame|reconnect|WebSocket|NostrPublicReadAdapter|location\.|process\.env|\.publish\(|\bsign\w*\(|type=["']password/i);
});
