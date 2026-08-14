import test from "node:test";
import assert from "node:assert/strict";
import { isCanonicalNip07PublicKey, NIP07_SELECTION_STATE, selectNip07PublicKey } from "../src/dev/nip07-public-key-selector.mjs";

const key = "a".repeat(64);

test("import is inert and a valid explicit selection returns only a canonical key", async () => {
  let resolved = 0; let calls = 0;
  assert.equal(resolved, 0);
  const result = await selectNip07PublicKey({ resolveProvider: () => { resolved += 1; return { getPublicKey: async () => { calls += 1; return key; } }; } });
  assert.deepEqual(result, { state: NIP07_SELECTION_STATE.selected, publicKey: key });
  assert.equal(resolved, 1); assert.equal(calls, 1);
  assert.deepEqual(Object.keys(result), ["state", "publicKey"]);
});

test("missing and malformed providers fail with a fixed unavailable state", async () => {
  const hostile = "extension private failure";
  const cases = [() => undefined, () => null, () => 1, () => Object.assign(() => {}, { getPublicKey: async () => key }), () => ({}), () => ({ getPublicKey: 1 }), () => { throw new Error(hostile); }, () => Object.defineProperty({}, "getPublicKey", { get() { throw new Error(hostile); } })];
  for (const resolveProvider of cases) assert.deepEqual(await selectNip07PublicKey({ resolveProvider }), { state: NIP07_SELECTION_STATE.unavailable });
});

test("throws, rejections, and timeout are sanitized and one attempt calls once", async () => {
  for (const getPublicKey of [() => { throw new Error("hostile secret"); }, async () => { throw new Error("hostile secret"); }]) {
    assert.deepEqual(await selectNip07PublicKey({ resolveProvider: () => ({ getPublicKey }) }), { state: NIP07_SELECTION_STATE.unavailable });
  }
  let calls = 0; let fire;
  const pending = selectNip07PublicKey({ resolveProvider: () => ({ getPublicKey: () => { calls += 1; return new Promise(() => {}); } }), timeoutMs: 1, setTimer: (callback) => { fire = callback; return 7; }, clearTimer: () => {} });
  await Promise.resolve(); fire();
  assert.deepEqual(await pending, { state: NIP07_SELECTION_STATE.unavailable });
  assert.equal(calls, 1);
});

test("only primitive canonical lowercase x-only keys are accepted", async () => {
  const invalid = [new String(key), [], {}, key.toUpperCase(), ` ${key}`, `${key} `, `0x${key}`, `npub${key}`, key.slice(1), `${key}0`];
  for (const value of invalid) {
    const result = await selectNip07PublicKey({ resolveProvider: () => ({ getPublicKey: async () => value }) });
    assert.deepEqual(result, { state: NIP07_SELECTION_STATE.invalid });
  }
  assert.equal(isCanonicalNip07PublicKey(key), true);
});

test("a direct attacker thenable is rejected without invoking its then method", async () => {
  let thenCalls = 0;
  const attacker = { then(resolve) { thenCalls += 1; resolve(key); } };
  const result = await selectNip07PublicKey({ resolveProvider: () => ({ getPublicKey: () => attacker }) });
  assert.deepEqual(result, { state: NIP07_SELECTION_STATE.invalid });
  assert.equal(thenCalls, 0);
});
