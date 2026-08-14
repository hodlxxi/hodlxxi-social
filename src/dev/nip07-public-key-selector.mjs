export const NIP07_SELECTION_STATE = Object.freeze({
  unavailable: "Extension unavailable",
  invalid: "Invalid extension key",
  selected: "Extension key selected"
});

export const isCanonicalNip07PublicKey = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

const fixedResult = (state, publicKey = null) => Object.freeze(publicKey === null ? { state } : { state, publicKey });

export async function selectNip07PublicKey({ resolveProvider, timeoutMs = 5000, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  if (typeof resolveProvider !== "function" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) return fixedResult(NIP07_SELECTION_STATE.unavailable);

  let provider;
  let getPublicKey;
  try {
    provider = resolveProvider();
    if (typeof provider !== "object" || provider === null) return fixedResult(NIP07_SELECTION_STATE.unavailable);
    getPublicKey = provider.getPublicKey;
    if (typeof getPublicKey !== "function") return fixedResult(NIP07_SELECTION_STATE.unavailable);
  } catch {
    return fixedResult(NIP07_SELECTION_STATE.unavailable);
  }

  let timer;
  try {
    const directResult = getPublicKey.call(provider);
    let selection;
    if ((typeof directResult === "object" && directResult !== null) || typeof directResult === "function") {
      try {
        selection = Promise.prototype.then.call(directResult, (value) => value);
      } catch {
        return fixedResult(NIP07_SELECTION_STATE.invalid);
      }
    } else {
      selection = Promise.resolve(directResult);
    }
    const timeout = new Promise((_, reject) => { timer = setTimer(() => reject(new Error("selection timeout")), timeoutMs); });
    const value = await Promise.race([selection, timeout]);
    return isCanonicalNip07PublicKey(value) ? fixedResult(NIP07_SELECTION_STATE.selected, value) : fixedResult(NIP07_SELECTION_STATE.invalid);
  } catch {
    return fixedResult(NIP07_SELECTION_STATE.unavailable);
  } finally {
    provider = undefined;
    getPublicKey = undefined;
    if (timer !== undefined) clearTimer(timer);
  }
}
