const HEX64 = /^[0-9a-f]{64}$/;
const DEFAULT_TIMEOUT_MS = 15_000;

const unavailable = () => {
  throw new TypeError("messaging device signer unavailable");
};

const ownedPromise = (value) => {
  if (
    (typeof value === "object" && value !== null) ||
    typeof value === "function"
  ) {
    try {
      return Promise.prototype.then.call(value, (result) => result);
    } catch {
      unavailable();
    }
  }
  return Promise.resolve(value);
};

export function createNip46MessagingDeviceSigner({
  publicKey,
  request,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  signal,
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout
} = {}) {
  if (
    !HEX64.test(publicKey) || typeof request !== "function" ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 ||
    typeof setTimer !== "function" || typeof clearTimer !== "function" ||
    (signal !== undefined && (
      signal === null || typeof signal !== "object" ||
      typeof signal.addEventListener !== "function" ||
      typeof signal.removeEventListener !== "function"
    ))
  ) unavailable();

  let used = false;
  return Object.freeze({
    async signEventForSubject({ subject, unsignedEvent } = {}) {
      if (used || !HEX64.test(subject) || subject !== publicKey || signal?.aborted === true) unavailable();
      used = true;
      let timer;
      let abort;
      try {
        const pending = request(Object.freeze({
          method: "sign_event",
          params: Object.freeze([unsignedEvent])
        }));
        const timeout = new Promise((_, reject) => {
          timer = setTimer(
            () => reject(new TypeError("messaging device signer timeout")),
            timeoutMs
          );
        });
        const cancelled = new Promise((_, reject) => {
          if (!signal) return;
          abort = () => reject(new TypeError("messaging device signer cancelled"));
          signal.addEventListener("abort", abort, { once: true });
        });
        return await Promise.race([ownedPromise(pending), timeout, cancelled]);
      } catch {
        unavailable();
      } finally {
        if (timer !== undefined) clearTimer(timer);
        if (abort) signal.removeEventListener("abort", abort);
      }
    }
  });
}
