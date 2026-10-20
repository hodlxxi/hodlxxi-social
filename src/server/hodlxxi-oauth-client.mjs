import { createHash, randomBytes } from "node:crypto";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype && Object.getOwnPropertySymbols(value).length === 0 && Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) => descriptor.enumerable && Object.hasOwn(descriptor, "value"));
const bounded = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
const failure = () => { throw new Error("oauth_request_failed"); };
const MAX_OAUTH_RESPONSE_BYTES = 16384;
const MAX_DIAGNOSTIC_BYTES = MAX_OAUTH_RESPONSE_BYTES + 1;
const MAX_DIAGNOSTIC_ELAPSED_MS = 60000;
const JSON_CONTENT_TYPE = /^application\/json(?:[\t ]*;[\t ]*[!#$%&'*+\-.^_`|~0-9A-Za-z]+[\t ]*=[\t ]*(?:[!#$%&'*+\-.^_`|~0-9A-Za-z]+|"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e]|\\[\t\x20-\x7e])*"))*[\t ]*$/i;
const rejectDuplicateJsonMembers = (source) => {
  let offset = 0;
  const whitespace = () => { while (/\s/.test(source[offset] ?? "")) offset += 1; };
  const string = () => {
    const start = offset++;
    let escaped = false;
    while (offset < source.length) {
      const character = source[offset++];
      if (!escaped && character === '"') return JSON.parse(source.slice(start, offset));
      if (!escaped && character === "\\") escaped = true; else escaped = false;
    }
    failure();
  };
  const value = () => {
    whitespace();
    if (source[offset] === '"') { string(); return; }
    if (source[offset] === "{") {
      offset += 1; whitespace();
      const names = new Set();
      if (source[offset] === "}") { offset += 1; return; }
      while (offset < source.length) {
        if (source[offset] !== '"') failure();
        const name = string(); if (names.has(name)) failure(); names.add(name);
        whitespace(); if (source[offset++] !== ":") failure(); value(); whitespace();
        const separator = source[offset++]; if (separator === "}") return; if (separator !== ",") failure(); whitespace();
      }
      failure();
    }
    if (source[offset] === "[") {
      offset += 1; whitespace();
      if (source[offset] === "]") { offset += 1; return; }
      while (offset < source.length) { value(); whitespace(); const separator = source[offset++]; if (separator === "]") return; if (separator !== ",") failure(); whitespace(); }
      failure();
    }
    const start = offset;
    while (offset < source.length && !/[\s,}\]]/.test(source[offset])) offset += 1;
    if (start === offset) failure();
  };
  whitespace(); value(); whitespace(); if (offset !== source.length) failure();
};
export const base64url = (bytes) => Buffer.from(bytes).toString("base64url");
export const createPkceVerifier = (random = randomBytes) => base64url(random(32));
export const createPkceChallenge = (verifier) => base64url(createHash("sha256").update(verifier, "ascii").digest());

const createRejectedResponseDisposer = (controller) => {
  let disposed = false;
  return (response) => {
    if (disposed) return;
    disposed = true;
    try { controller.abort(); } catch {}
    let body;
    try { body = response?.body; } catch { return; }
    let cancel;
    try { cancel = body?.cancel; } catch { return; }
    if (typeof cancel !== "function") return;
    try {
      const cancellation = cancel.call(body);
      Promise.resolve(cancellation).catch(() => {});
    } catch {}
  };
};

const diagnosticClock = (nowImpl) => {
  try {
    const value = nowImpl();
    return Number.isFinite(value) ? value : null;
  } catch { return null; }
};

const diagnosticElapsed = (startedAt, nowImpl) => {
  const finishedAt = diagnosticClock(nowImpl);
  if (startedAt === null || finishedAt === null) return 0;
  return Math.max(0, Math.min(MAX_DIAGNOSTIC_ELAPSED_MS, Math.trunc(finishedAt - startedAt)));
};

const diagnosticByteCount = (value) => Math.min(value, MAX_DIAGNOSTIC_BYTES);

const reportFailure = (reporter, observation, startedAt, nowImpl, timedOut, aborted) => {
  if (typeof reporter !== "function") return;
  const record = {
    endpoint: observation.endpoint,
    stage: observation.stage,
    elapsedMs: diagnosticElapsed(startedAt, nowImpl),
    receivedBytes: observation.receivedBytes,
    timedOut,
    aborted
  };
  if (observation.status !== undefined) record.status = observation.status;
  if (observation.declaredBytes !== undefined) record.declaredBytes = observation.declaredBytes;
  try {
    const reporting = reporter(Object.freeze(record));
    Promise.resolve(reporting).catch(() => {});
  } catch {}
};

async function readBoundedBody(response, observation) {
  observation.stage = "body";
  if (!response.body || typeof response.body.getReader !== "function") failure();
  observation.stage = "declared_size";
  const declared = response.headers?.get?.("content-length");
  if (typeof declared === "string" && /^[0-9]+$/.test(declared)) {
    const numeric = Number(declared);
    observation.declaredBytes = Number.isFinite(numeric) ? diagnosticByteCount(numeric) : MAX_DIAGNOSTIC_BYTES;
  }
  if (declared !== null && declared !== undefined && (typeof declared !== "string" || !/^[0-9]+$/.test(declared) || Number(declared) > MAX_OAUTH_RESPONSE_BYTES)) failure();
  observation.stage = "body_reader";
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      observation.stage = "body_read";
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) failure();
      length += value.byteLength;
      observation.receivedBytes = diagnosticByteCount(length);
      if (length > MAX_OAUTH_RESPONSE_BYTES) {
        observation.stage = "received_size";
        failure();
      }
      chunks.push(value);
    }
  } finally {
    const precedingStage = observation.stage;
    try { reader.releaseLock(); } catch { observation.stage = "body_release"; failure(); }
    observation.stage = precedingStage;
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  observation.stage = "decode";
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { failure(); }
}

async function postForm(endpoint, url, fields, accept, { fetchImpl, timeoutMs, setTimeoutImpl = setTimeout, clearTimeoutImpl = clearTimeout, diagnosticReporter, nowImpl = Date.now }) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeoutImpl(() => { timedOut = true; controller.abort(); }, timeoutMs);
  const dispose = createRejectedResponseDisposer(controller);
  const observation = { endpoint, stage: "dispatch", receivedBytes: 0 };
  const startedAt = typeof diagnosticReporter === "function" ? diagnosticClock(nowImpl) : null;
  let response;
  let result;
  let accepted = false;
  let timedOutAtFailure = false;
  let abortedAtFailure = false;
  try {
    response = await fetchImpl(url, { method: "POST", redirect: "manual", credentials: "omit", signal: controller.signal,
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() });
    observation.stage = "status";
    const status = response?.status;
    if (Number.isSafeInteger(status) && status >= 0 && status <= 599) observation.status = status;
    if (!response || status !== 200) failure();
    observation.stage = "content_type";
    const contentType = response.headers?.get?.("content-type");
    if (typeof contentType !== "string" || !JSON_CONTENT_TYPE.test(contentType)) failure();
    const raw = await readBoundedBody(response, observation);
    let value;
    try {
      observation.stage = "json_members";
      rejectDuplicateJsonMembers(raw);
      observation.stage = "json_parse";
      value = JSON.parse(raw);
    } catch { failure(); }
    observation.stage = "response_validation";
    result = accept(value);
    accepted = true;
  } catch {
    timedOutAtFailure = timedOut;
    abortedAtFailure = controller.signal.aborted;
    dispose(response);
  } finally {
    if (!accepted) dispose(response);
    try { clearTimeoutImpl(timer); } catch {}
  }
  if (!accepted) {
    reportFailure(diagnosticReporter, observation, startedAt, nowImpl, timedOutAtFailure, abortedAtFailure);
    failure();
  }
  return result;
}

export function validateTokenResponse(value) {
  const allowed = new Set(["access_token", "id_token", "token_type", "expires_in", "scope"]);
  if (!plain(value) || Object.keys(value).some((name) => !allowed.has(name)) || !bounded(value.access_token, 8192) || value.token_type !== "Bearer") failure();
  if (Object.hasOwn(value, "id_token") && !bounded(value.id_token, 8192)) failure();
  if (Object.hasOwn(value, "expires_in") && (!Number.isSafeInteger(value.expires_in) || value.expires_in < 1 || value.expires_in > 86400)) failure();
  if (Object.hasOwn(value, "scope") && !bounded(value.scope, 1024)) failure();
  return value.access_token;
}
const scopeTokens = (value) => {
  if (!bounded(value, 8192)) failure();
  const tokens = value.split(" ");
  // RFC 6749 section 3.3: nonempty scope tokens separated by one ASCII space.
  if (tokens.some((token) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(token))) failure();
  return tokens;
};

export function validateIntrospectionResponse(value, { clientId, scope }) {
  if (!plain(value) || value.active !== true || typeof value.sub !== "string" || !/^[0-9a-f]{64}$/.test(value.sub)) failure();
  for (const item of Object.values(value)) {
    if (!["string", "number", "boolean"].includes(typeof item) || typeof item === "string" && !bounded(item, 8192)) failure();
    if (typeof item === "number" && (!Number.isSafeInteger(item) || item < 0)) failure();
  }
  if (Object.hasOwn(value, "client_id") && value.client_id !== clientId) failure();
  if (!Object.hasOwn(value, "scope")) failure();
  const granted = new Set(scopeTokens(value.scope));
  if (!scopeTokens(scope).every((token) => granted.has(token))) failure();
  return value.sub;
}

export function createHodlxxiOAuthClient(config, dependencies = {}) {
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new TypeError("invalid transport");
  const transport = {
    fetchImpl,
    timeoutMs: config.outboundTimeoutMs,
    setTimeoutImpl: dependencies.setTimeoutImpl,
    clearTimeoutImpl: dependencies.clearTimeoutImpl,
    diagnosticReporter: dependencies.diagnosticReporter,
    nowImpl: dependencies.nowImpl
  };
  return Object.freeze({
    async authenticate({ code, verifier }) {
      if (!bounded(code, 2048) || !bounded(verifier, 128)) failure();
      const token = await postForm("token", `${config.authorityOrigin}/oauth/token`, {
        grant_type: "authorization_code", code, redirect_uri: config.callbackUri, client_id: config.clientId,
        client_secret: config.clientSecret, code_verifier: verifier
      }, validateTokenResponse, transport);
      const subject = await postForm("introspection", `${config.authorityOrigin}/oauth/introspect`, {
        token, client_id: config.clientId, client_secret: config.clientSecret
      }, (value) => validateIntrospectionResponse(value, config), transport);
      return Object.freeze({
        subject,
        accessToken: token
      });
    }
  });
}
