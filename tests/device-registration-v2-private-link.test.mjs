import test from "node:test";
import assert from "node:assert/strict";
import { makePrivatePhoneLink, takePrivatePairingFragment } from "../web/device-registration-v2-private-link.mjs";
const qr = "hodlxxi-social-pair:v1:" + "a".repeat(64) + ":" + "b".repeat(64);
const base = "https://social-preview.hodlxxi.test:9544/device-registration-v2.html";
test("one-time private pairing link is kept in fragment, removed synchronously, and canonical", () => {
  const link = makePrivatePhoneLink(qr, base);
  const url = new URL(link);
  assert.equal(url.origin, "https://social-preview.hodlxxi.test:9544");
  assert.equal(url.pathname, "/device-registration-v2.html");
  assert.equal(url.search, "");
  assert.equal(url.hash.startsWith("#pair="), true);
  let cleared = false;
  const recovered = takePrivatePairingFragment(link, path => {
    cleared = true;
    assert.equal(path, "/device-registration-v2.html");
  });
  assert.equal(cleared, true);
  assert.equal(recovered, qr);
  assert.equal(takePrivatePairingFragment(base, () => assert.fail()), null);
});
test("invalid, cross-origin and ambiguous private pairing links fail closed", () => {
  for (const candidate of [
    "http://social-preview.hodlxxi.test:9544/device-registration-v2.html",
    "https://social-preview.hodlxxi.test:9544/device-registration-v2.html?code=1",
    "https://social-preview.hodlxxi.test:9544/other",
    "https://alice:secret@social-preview.hodlxxi.test:9544/device-registration-v2.html",
    base + "#already"
  ]) assert.throws(() => makePrivatePhoneLink(qr, candidate), /private pairing link unavailable/);
  assert.throws(() => makePrivatePhoneLink(qr.toUpperCase(), base));
  let cleared = false;
  assert.throws(() => takePrivatePairingFragment(base+"#pair=invalid", () => {cleared = true;}));
  assert.equal(cleared, true);
  assert.throws(() => takePrivatePairingFragment(base+"#pair="+encodeURIComponent(qr), () => {throw new Error("history failed");}));
});
