// Ordinary entry only. This module never acquires a signer or device key.
const unavailable = () => { throw new Error("Social entry unavailable"); };
const exact = (value, names) => {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some((name) => !Object.hasOwn(value, name))) unavailable();
  return value;
};

export function createSocialEntryActions({ fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  if (typeof fetchImpl !== "function" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) unavailable();
  let busy = false, logoutCsrf;
  async function request(path, { method = "GET", body, csrf } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(path, {
        method, credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(csrf ? { "x-hodlxxi-mobile-csrf": csrf } : {}) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: controller.signal
      });
      if (response.status !== 200 || response.redirected ||
          response.headers?.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") unavailable();
      // Stop reading at the byte bound; never buffer an unbounded response.
      const reader = response.body?.getReader();
      if (!reader) unavailable();
      const chunks = []; let size = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > 1024) unavailable();
          chunks.push(part.value);
        }
      } finally { void reader.cancel().catch(() => {}); reader.releaseLock(); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } finally { controller.abort(); clearTimeout(timer); }
  }
  async function mode() {
    const value = exact(await request("/auth/entry-config"), ["mobileContextRequired"]);
    if (typeof value.mobileContextRequired !== "boolean") unavailable();
    return value.mobileContextRequired;
  }
  async function context(purpose) {
    const value = exact(await request("/auth/mobile/v1/context", { method: "POST", body: { purpose } }), ["csrf"]);
    if (typeof value.csrf !== "string" || !/^[0-9a-f]{64}$/.test(value.csrf)) unavailable();
    return value.csrf;
  }
  async function exclusive(action) {
    if (busy) unavailable();
    busy = true;
    try { return await action(); } catch { unavailable(); } finally { busy = false; }
  }
  return Object.freeze({
    login() { return exclusive(async () => {
      if (await mode()) await context("login");
      return "/auth/login";
    }); },
    logout() { return exclusive(async () => {
      const mobile = logoutCsrf !== undefined || await mode();
      if (mobile && logoutCsrf === undefined) logoutCsrf = await context("logout");
      const value = await request("/auth/logout", mobile
        ? { method: "POST", body: {}, csrf: logoutCsrf } : { method: "POST" });
      exact(value, mobile ? ["authenticated", "logout"] : ["authenticated"]);
      if (value.authenticated !== false || mobile && !["confirmed", "local-only"].includes(value.logout)) unavailable();
      logoutCsrf = undefined;
      return Object.freeze({ authenticated: false });
    }); }
  });
}
