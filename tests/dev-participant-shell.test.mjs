import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SOCIAL_AUTHORITY_PROJECTION_SCHEMA } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { createParticipantShellSnapshot } from "../src/dev/hodlxxi-participant-shell-snapshot.mjs";
import { bindParticipantShell } from "../web/dev-participant-shell.mjs";

const subject = "c".repeat(64);
const options = { origin: "https://authority.example", relayUrl: "wss://relay.example/", subject, timeoutMs: 5000, noteLimit: 3 };
const projection = (status = "full") => Object.freeze({ schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA, version: 1, subject, assertedIdentityClass: status, valid: true, diagnostic: "asserted", evidenceSource: "safe", observedAt: status === "full" ? "2026-08-14T00:00:00+00:00" : null });
const result = (overrides = {}) => ({ subject, relayUrl: options.relayUrl, noteLimit: 3, authority: { status: "fulfilled", value: projection() }, profile: { status: "fulfilled", value: { id: subject, publicKey: subject, displayName: "Ada <script>" } }, notes: { status: "fulfilled", value: [{ id: "n", authorId: subject, audience: "PUBLIC", body: "<img onerror=alert(1)>", timestamp: "now", reactions: 0, comments: 0, reposts: 0, replies: [] }] }, ...overrides });

class Element {
  constructor() { this.listeners = new Map(); this.value = ""; this.disabled = false; this.button = null; this.innerHTML = ""; this._text = ""; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  querySelector(selector) { return selector === 'button[type="submit"]' ? this.button : null; }
  querySelectorAll() { return []; }
  set textContent(value) { this._text = value; }
  get textContent() { return this._text; }
}
function fakeDocument() {
  const ids = ["#participant-shell-form", "#shell-select-extension-key", "#shell-extension-state", "#shell-origin", "#shell-relay", "#shell-subject", "#shell-timeout", "#shell-note-limit", "#shell-selected-key", "#shell-freshness", "#shell-profile-state", "#shell-feed-state", "#shell-navigation", "#shell-profile", "#shell-feed"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  elements["#participant-shell-form"].button = new Element();
  Object.assign(elements["#shell-origin"], { value: options.origin }); Object.assign(elements["#shell-relay"], { value: options.relayUrl }); Object.assign(elements["#shell-subject"], { value: subject }); Object.assign(elements["#shell-timeout"], { value: "5000" }); Object.assign(elements["#shell-note-limit"], { value: "3" });
  return { elements, querySelector: (selector) => elements[selector] };
}
const submit = (binding) => binding.form.listeners.get("submit")({ preventDefault() {} });
const selectExtension = (binding) => binding.selectionButton.listeners.get("click")({ preventDefault() {} });
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

test("idle and invalid input perform zero reads", async () => {
  const document = fakeDocument(); let reads = 0;
  const binding = bindParticipantShell(document, { parse: () => { throw new TypeError("invalid"); }, load: async () => { reads += 1; } });
  assert.equal(reads, 0); await submit(binding); assert.equal(reads, 0);
  assert.match(document.elements["#shell-freshness"].textContent, /no reads/);
});

test("provider resolution waits for selection and selection remains separate from participant loading", async () => {
  const document = fakeDocument(); document.elements["#shell-subject"].value = ""; let resolves = 0; let keyCalls = 0; let loads = 0;
  const binding = bindParticipantShell(document, { resolveProvider: () => { resolves += 1; return { getPublicKey: async () => { keyCalls += 1; return subject; } }; }, load: async () => { loads += 1; return result(); } });
  assert.equal(resolves, 0); assert.equal(keyCalls, 0); assert.equal(loads, 0);
  await selectExtension(binding);
  assert.equal(resolves, 1); assert.equal(keyCalls, 1); assert.equal(loads, 0);
  assert.equal(document.elements["#shell-subject"].value, subject);
  assert.equal(document.elements["#shell-extension-state"].textContent, "Extension key selected");
  assert.equal(binding.selectionButton.disabled, false);
});

test("selection retains an exact match and rejects mismatch or malformed manual subjects", async () => {
  for (const [manual, expected] of [[subject, "Extension key selected — exact match"], ["d".repeat(64), "Subject mismatch"], ["malformed", "Invalid manual subject"]]) {
    const document = fakeDocument(); document.elements["#shell-subject"].value = manual; let loads = 0; let selections = 0;
    const binding = bindParticipantShell(document, { selectKey: async () => { selections += 1; return { state: "Extension key selected", publicKey: subject }; }, load: async () => { loads += 1; } });
    await selectExtension(binding);
    assert.equal(document.elements["#shell-subject"].value, manual); assert.equal(document.elements["#shell-extension-state"].textContent, expected); assert.equal(loads, 0);
    assert.equal(selections, manual === "malformed" ? 0 : 1);
  }
});

test("malformed manual input prevents provider resolution and getPublicKey access", async () => {
  const document = fakeDocument(); document.elements["#shell-subject"].value = "not-canonical"; let resolves = 0; let keyCalls = 0;
  const binding = bindParticipantShell(document, { resolveProvider: () => { resolves += 1; return { getPublicKey: () => { keyCalls += 1; return subject; } }; } });
  await selectExtension(binding);
  assert.equal(resolves, 0); assert.equal(keyCalls, 0);
  assert.equal(document.elements["#shell-extension-state"].textContent, "Invalid manual subject");
});

test("concurrent extension selection is rejected, failures restore controls, and later selection is possible", async () => {
  const document = fakeDocument(); const first = deferred(); let calls = 0;
  const binding = bindParticipantShell(document, { selectKey: () => { calls += 1; return calls === 1 ? first.promise : Promise.resolve({ state: "Extension unavailable" }); } });
  const pending = selectExtension(binding); await selectExtension(binding); assert.equal(calls, 1); assert.equal(binding.selectionButton.disabled, true);
  first.reject(new Error("hostile extension text")); await pending;
  assert.equal(binding.selectionButton.disabled, false); assert.equal(document.elements["#shell-extension-state"].textContent, "Extension unavailable");
  await selectExtension(binding); assert.equal(calls, 2);
});

test("one accepted submission renders escaped existing profile, badge, and feed output", async () => {
  const document = fakeDocument(); let calls = 0;
  const binding = bindParticipantShell(document, { parse: () => options, load: async () => { calls += 1; return result(); } });
  await submit(binding);
  assert.equal(calls, 1); assert.equal(document.elements["#shell-selected-key"].textContent, subject);
  assert.match(document.elements["#shell-profile"].innerHTML, /badge-full/);
  assert.match(document.elements["#shell-profile"].innerHTML, /Ada &lt;script&gt;/);
  assert.match(document.elements["#shell-feed"].innerHTML, /&lt;img onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(document.elements["#shell-profile"].innerHTML + document.elements["#shell-feed"].innerHTML, /<script>|<img onerror/);
  assert.equal(binding.form.button.disabled, false);
});

test("concurrency is rejected, controls restore after failure, and later submission runs", async () => {
  const document = fakeDocument(); const first = deferred(); let calls = 0;
  const binding = bindParticipantShell(document, { parse: () => options, load: () => { calls += 1; return calls === 1 ? first.promise : Promise.resolve(result()); } });
  const pending = submit(binding); await submit(binding); assert.equal(calls, 1); first.reject(new Error("private transport")); await pending;
  assert.equal(binding.form.button.disabled, false); await submit(binding); assert.equal(calls, 2);
});

test("a later failed submission clears every prior successful product region", async () => {
  const document = fakeDocument(); let calls = 0;
  const binding = bindParticipantShell(document, { parse: () => options, load: async () => { calls += 1; if (calls === 2) throw new Error("private failure"); return result(); } });
  await submit(binding);
  assert.match(document.elements["#shell-profile"].innerHTML, /badge-full/);
  assert.match(document.elements["#shell-feed"].innerHTML, /onerror/);
  await submit(binding);
  assert.doesNotMatch(document.elements["#shell-profile"].innerHTML, /badge-full|Ada/);
  assert.doesNotMatch(document.elements["#shell-feed"].innerHTML, /onerror|post-card/);
  assert.equal(document.elements["#shell-navigation"].innerHTML, "");
  assert.equal(document.elements["#shell-profile-state"].textContent, "Profile unavailable");
  assert.equal(document.elements["#shell-feed-state"].textContent, "Public feed unavailable");
});

test("independent empty states remain visible and fail-closed", async () => {
  const document = fakeDocument();
  const value = result({ authority: { status: "rejected", reason: new Error("secret") }, profile: { status: "fulfilled", value: null }, notes: { status: "fulfilled", value: [] } });
  await submit(bindParticipantShell(document, { parse: () => options, load: async () => value, map: createParticipantShellSnapshot }));
  assert.match(document.elements["#shell-profile"].innerHTML, /badge-limited/);
  assert.match(document.elements["#shell-profile-state"].textContent, /public-key-only/);
  assert.equal(document.elements["#shell-feed-state"].textContent, "No public notes");
  assert.doesNotMatch(Object.values(document.elements).map((item) => item.textContent).join(" "), /secret|transport/i);
});

test("rejected fulfilled profile data is labelled as public-key-only", async () => {
  for (const profile of [{ id: "d".repeat(64), publicKey: "d".repeat(64), displayName: "Mismatch" }, { id: subject, publicKey: subject, displayName: "" }]) {
    const document = fakeDocument();
    await submit(bindParticipantShell(document, { parse: () => options, load: async () => result({ profile: { status: "fulfilled", value: profile } }) }));
    assert.equal(document.elements["#shell-profile-state"].textContent, "Profile unavailable — public-key-only identity");
    assert.doesNotMatch(document.elements["#shell-profile"].innerHTML, /Mismatch/);
  }
});

test("Operator-bearing public display records are absent from complete rendered output", async () => {
  const document = fakeDocument();
  const value = result({ profile: { status: "fulfilled", value: { id: subject, publicKey: subject, displayName: "OPERATOR claim" } }, notes: { status: "fulfilled", value: [{ id: "op", authorId: subject, audience: "PUBLIC", body: "operator text", timestamp: "now", reactions: 0, comments: 0, reposts: 0, replies: [] }] } });
  await submit(bindParticipantShell(document, { parse: () => options, load: async () => value }));
  const rendered = ["#shell-profile", "#shell-feed"].map((id) => document.elements[id].innerHTML).join(" ");
  assert.doesNotMatch(rendered, /operator/i);
  assert.equal(document.elements["#shell-feed-state"].textContent, "No public notes");
});

test("surface is isolated, read-only, responsive, and preserves ordinary explicit bootstrap", async () => {
  const [html, module, css, app, index] = await Promise.all(["dev-participant-shell.html", "dev-participant-shell.mjs", "styles.css", "app.mjs", "demo.html"].map((name) => readFile(new URL(`../web/${name}`, import.meta.url), "utf8")));
  assert.match(html, /DEV \/ LIVE READ-ONLY PRODUCT SHELL/); assert.match(html, /EXPLICIT PUBLIC KEY \/ NOT AUTHENTICATED/); assert.match(html, /HODLXXI AUTHORITY \+ PUBLIC NOSTR SOURCES/);
  assert.match(html, /EXTENSION-SELECTED KEY \/ NOT AUTHENTICATED/); assert.match(html, /Select key from NIP-07 extension/);
  assert.doesNotMatch(html, /viewer-select|local-composer|message-composer|data-action="react"/);
  assert.doesNotMatch(module + html, /localStorage|sessionStorage|indexedDB|serviceWorker|setInterval|\.publish\(|sign\w*\(|\b(?:POST|PUT|PATCH|DELETE)\b/);
  assert.match(css, /live-product-grid/); assert.match(css, /@media\(max-width:720px\).*live-product-grid/s);
  assert.match(index, /data-hodlxxi-synthetic-app/); assert.match(app, /bootstrapSyntheticApp/);
  assert.match(module, /renderPageFrame/); assert.match(module, /renderNavigation/);
  assert.match(app, /let fixtureData;\s*function getFixtureData\(\)/);
  assert.doesNotMatch(app.slice(0, app.indexOf("function getFixtureData")), /\.load\(\)/);
  assert.match(app, /renderApp\(root, getFixtureData\(\), browser\)/);
  assert.doesNotMatch(app, /hodlxxi-participant-live-composition|WebSocketNostrReadTransport/);
  assert.doesNotMatch(app + index, /NIP-07|nip07|window\.nostr/);
});
