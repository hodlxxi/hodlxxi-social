import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SOCIAL_AUTHORITY_PROJECTION_SCHEMA } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { bindDevParticipantPage } from "../web/dev-participant.mjs";

const subject = "a".repeat(64);
const options = { origin: "https://authority.example", relayUrl: "wss://relay.example/", subject, timeoutMs: 5000, noteLimit: 3 };
const projection = (overrides = {}) => ({ assertedIdentityClass: "full", evidenceSource: "safe", observedAt: "2026-08-14T00:00:00Z", ...overrides });
const validProjection = (assertedIdentityClass, overrides = {}) => Object.freeze({
  schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass, valid: true,
  diagnostic: "asserted", evidenceSource: "safe", observedAt: "2026-08-14T00:00:00+00:00", ...overrides
});
const settled = (overrides = {}) => ({
  subject, relayUrl: options.relayUrl, noteLimit: 3,
  authority: { status: "fulfilled", value: projection() },
  profile: { status: "fulfilled", value: { id: subject, displayName: "Ada" } },
  notes: { status: "fulfilled", value: [{ authorId: subject, timestamp: "2026-08-14T00:00:00.000Z", body: "hello" }] },
  ...overrides
});

class Element {
  constructor(name = "div") { this.name = name; this.listeners = new Map(); this.children = []; this.value = ""; this.disabled = false; this.button = null; this._textContent = ""; this.writes = []; }
  set textContent(value) { this._textContent = value; this.writes.push(value); }
  get textContent() { return this._textContent; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  querySelector(selector) { return selector === 'button[type="submit"]' ? this.button : null; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = [...children]; }
}

function fakeDocument() {
  const ids = ["#dev-participant-form", "#participant-origin", "#participant-relay-input", "#participant-subject", "#participant-timeout", "#participant-note-limit", "#participant-selected-subject", "#participant-authority-class", "#participant-authority-state", "#participant-authority-diagnostic", "#participant-authority-evidence", "#participant-authority-observed", "#participant-relay", "#participant-profile-state", "#participant-profile-name", "#participant-notes-state", "#participant-notes"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  elements["#dev-participant-form"].button = new Element("button");
  elements["#participant-origin"].value = options.origin;
  elements["#participant-relay-input"].value = options.relayUrl;
  elements["#participant-subject"].value = subject;
  elements["#participant-timeout"].value = "5000";
  elements["#participant-note-limit"].value = "3";
  return { elements, querySelector: (selector) => elements[selector], createElement: (name) => new Element(name) };
}
const submit = (binding) => binding.form.listeners.get("submit")({ preventDefault() {} });
const field = (document, id) => document.elements[id].textContent;
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

test("binding starts idle and invalid input performs zero reads without selecting input", async () => {
  const document = fakeDocument(); let calls = 0;
  const binding = bindDevParticipantPage(document, { parse: () => { throw new TypeError("invalid"); }, load: async () => { calls += 1; } });
  assert.equal(calls, 0);
  await submit(binding);
  assert.equal(calls, 0);
  assert.equal(field(document, "#participant-selected-subject"), "None");
  assert.equal(field(document, "#participant-authority-class"), "Limited");
});

test("validated subject is visible while loading and all successful data renders", async () => {
  const document = fakeDocument(); const pending = deferred();
  const binding = bindDevParticipantPage(document, { parse: () => options, load: () => pending.promise, format: () => {} });
  const completion = submit(binding);
  assert.equal(field(document, "#participant-selected-subject"), subject);
  assert.equal(field(document, "#participant-authority-state"), "Loading");
  assert.equal(binding.form.button.disabled, true);
  pending.resolve(settled()); await completion;
  assert.equal(field(document, "#participant-authority-class"), "Full");
  assert.equal(field(document, "#participant-profile-state"), "Profile available");
  assert.equal(field(document, "#participant-profile-name"), "Ada");
  assert.equal(field(document, "#participant-notes-state"), "Notes available");
  assert.equal(document.elements["#participant-notes"].children[0].children[1].textContent, "hello");
  assert.equal("dateTime" in document.elements["#participant-notes"].children[0].children[0], false);
  assert.equal(binding.form.button.disabled, false);
});

test("independent failures, empty states, formatter rejection, and evidence suppression are safe", async () => {
  const cases = [
    [settled({ authority: { status: "rejected", reason: new Error("secret") } }), "Limited", "Profile available", "Notes available"],
    [settled({ profile: { status: "rejected", reason: new Error("raw frame") }, notes: { status: "rejected", reason: new Error("transport") } }), "Full", "Profile unavailable — relay unavailable", "Relay unavailable"],
    [settled({ profile: { status: "fulfilled", value: null }, notes: { status: "fulfilled", value: [] } }), "Full", "Profile missing", "No public notes"],
    [settled({ authority: { status: "rejected", reason: new Error("secret") }, profile: { status: "rejected", reason: new Error("raw") }, notes: { status: "rejected", reason: new Error("raw") } }), "Limited", "Profile unavailable — relay unavailable", "Relay unavailable"]
  ];
  for (const [result, authorityClass, profileState, notesState] of cases) {
    const document = fakeDocument(); const binding = bindDevParticipantPage(document, { parse: () => options, load: async () => result, format: () => {} });
    await submit(binding);
    assert.equal(field(document, "#participant-authority-class"), authorityClass);
    assert.equal(field(document, "#participant-profile-state"), profileState);
    assert.equal(field(document, "#participant-notes-state"), notesState);
    assert.equal(field(document, "#participant-selected-subject"), subject);
    assert.doesNotMatch(Object.values(document.elements).map((value) => value.textContent).join(" "), /secret|raw frame|transport/i);
  }
  const suppressed = fakeDocument();
  await submit(bindDevParticipantPage(suppressed, { parse: () => options, load: async () => settled({ authority: { status: "fulfilled", value: projection({ evidenceSource: "xOPERATORish" }) } }), format: () => {} }));
  assert.equal(field(suppressed, "#participant-authority-evidence"), "Suppressed");
  const malformed = fakeDocument();
  await submit(bindDevParticipantPage(malformed, { parse: () => options, load: async () => settled(), format: () => { throw new TypeError("operator invalid"); } }));
  assert.equal(field(malformed, "#participant-authority-class"), "Limited");
});

test("real authority formatter permits only exact Full and Limited projections", async () => {
  for (const [assertedIdentityClass, displayed] of [["full", "Full"], ["limited", "Limited"]]) {
    const document = fakeDocument();
    const binding = bindDevParticipantPage(document, { parse: () => options, load: async () => settled({ authority: { status: "fulfilled", value: validProjection(assertedIdentityClass) } }) });
    await submit(binding);
    assert.equal(field(document, "#participant-authority-class"), displayed);
    assert.equal(field(document, "#participant-selected-subject"), subject);
  }
  const document = fakeDocument();
  await submit(bindDevParticipantPage(document, { parse: () => options, load: async () => settled({ authority: { status: "fulfilled", value: validProjection("operator") } }) }));
  assert.equal(field(document, "#participant-authority-class"), "Limited");
  assert.doesNotMatch(Object.values(document.elements).map((value) => value.textContent).join(" "), /operator/i);
  assert.equal(field(document, "#participant-selected-subject"), subject);
});

test("concurrent work is excluded, controls restore, and a later submit runs", async () => {
  const document = fakeDocument(); const first = deferred(); let calls = 0;
  const binding = bindDevParticipantPage(document, { parse: () => options, load: () => { calls += 1; return calls === 1 ? first.promise : Promise.resolve(settled()); }, format: () => {} });
  const completion = submit(binding); await submit(binding); assert.equal(calls, 1);
  first.reject(new Error("private")); await completion;
  assert.equal(binding.form.button.disabled, false);
  await submit(binding); assert.equal(calls, 2);
});

test("HTML, module, styles, and existing entrypoints preserve isolation and non-claims", async () => {
  const [html, module, styles, index, live, authority] = await Promise.all([
    readFile(new URL("../web/dev-participant.html", import.meta.url), "utf8"), readFile(new URL("../web/dev-participant.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/styles.css", import.meta.url), "utf8"), readFile(new URL("../web/index.html", import.meta.url), "utf8"),
    readFile(new URL("../web/dev-live.html", import.meta.url), "utf8"), readFile(new URL("../web/dev-authority.html", import.meta.url), "utf8")
  ]);
  assert.match(html, /DEV \/ UNIFIED LIVE PARTICIPANT PREVIEW/);
  assert.match(html, /HODLXXI EXTERNAL AUTHORITY/); assert.match(html, /NOSTR PUBLIC DATA/);
  assert.match(html, /does not authenticate.*prove ownership.*private-key possession.*production mode/is);
  assert.match(html, /href="\.\/index\.html"/); assert.match(html, /href="\.\/dev-live\.html"/); assert.match(html, /href="\.\/dev-authority\.html"/);
  assert.match(styles, /dev-participant-grid/); assert.match(styles, /@media\(max-width:720px\).*dev-participant-form/s);
  assert.doesNotMatch(module + html, /innerHTML|insertAdjacentHTML|document\.write|localStorage|sessionStorage|indexedDB|serviceWorker|\.publish\(|setInterval/);
  assert.doesNotMatch(index + live + authority, /dev-participant\.mjs/);
});
