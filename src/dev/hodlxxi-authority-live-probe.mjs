import { AccessStatus } from "../domain.mjs";

export const AUTHORITY_SOURCE = "hodlxxi-authority-probe";
export const AUTHORITY_SCHEMA = "hodlxxi.current_entitlement_assertion.v1";
export const AUTHORITY_EXIT_CODES = Object.freeze({ asserted: 0, argument: 2, denied: 3, unavailable: 4, malformed: 5, invalid: 6 });

const SUBJECT = /^[0-9a-f]{64}$/;
const MAX_BODY = 32768;
const SUCCESS_FIELDS = ["current_full_relation_satisfied", "evidence_source", "identity_class", "observed_at", "schema", "subject", "valid"];
const OPTION_FIELDS = ["origin", "subject", "timeoutMs"];
const ASSERTION_FIELDS = ["diagnostic", "evidenceSource", "observedAt", "schema", "source", "status", "subject", "valid", "version"];
const unsafeEvidence = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

const projection = (subject, diagnostic, extra = {}) => Object.freeze({
  source: AUTHORITY_SOURCE, schema: AUTHORITY_SCHEMA, version: 1,
  subject: SUBJECT.test(subject ?? "") ? subject : "0".repeat(64),
  status: AccessStatus.LIMITED, valid: false, diagnostic, ...extra
});

export class AuthorityProbeError extends Error {
  constructor(diagnostic, subject) {
    if (!Object.hasOwn(AUTHORITY_EXIT_CODES, diagnostic) || diagnostic === "asserted") throw new TypeError("unsupported authority diagnostic");
    super(`authority probe ${diagnostic}`);
    this.name = "AuthorityProbeError";
    this.diagnostic = diagnostic;
    this.assertion = projection(subject, diagnostic);
  }
}

const fail = (diagnostic, subject) => { throw new AuthorityProbeError(diagnostic, subject); };

export function validateAuthorityOrigin(value) {
  if (typeof value !== "string" || value.length === 0) fail("argument");
  let parsed;
  try { parsed = new URL(value); } catch { fail("argument"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || value !== parsed.origin) fail("argument");
  return value;
}

const validateSubject = (value) => {
  if (typeof value !== "string" || !SUBJECT.test(value)) fail("argument");
  return value;
};

const validateTimeout = (value) => {
  if (!Number.isSafeInteger(value) || value < 250 || value > 30000) fail("argument");
  return value;
};

const exactDataRecord = (value, fields) => {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const names = Object.keys(value).sort();
  if (names.length !== fields.length || names.some((name, index) => name !== [...fields].sort()[index])) return false;
  return Reflect.ownKeys(value).length === fields.length && fields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
  });
};

const validateOptions = (value) => {
  if (!exactDataRecord(value, OPTION_FIELDS)) fail("argument");
  return Object.freeze({ origin: validateAuthorityOrigin(value.origin), subject: validateSubject(value.subject), timeoutMs: validateTimeout(value.timeoutMs) });
};

export function parseAuthorityProbeArgs(argv) {
  if (!Array.isArray(argv)) fail("argument");
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const field = ({ "--origin": "origin", "--subject": "subject", "--timeout-ms": "timeoutMs" })[option];
    if (!field || Object.hasOwn(values, field) || index + 1 >= argv.length) fail("argument");
    values[field] = field === "timeoutMs" && /^\d+$/.test(argv[index + 1]) ? Number(argv[index + 1]) : argv[index + 1];
  }
  return validateOptions(values);
}

const canonicalTimestamp = (value) => {
  if (typeof value !== "string" || value.length > 32) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{6})?\+00:00$/.exec(value);
  if (!match) return false;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day && date.getUTCHours() === hour && date.getUTCMinutes() === minute && date.getUTCSeconds() === second;
};
const safeProjectionEvidence = (value) => typeof value === "string" && value.length > 0 && value.trim() === value && [...value].length <= 128 && !unsafeEvidence.test(value);

const validateSuccess = (raw, subject) => {
  if (!exactDataRecord(raw, SUCCESS_FIELDS) || raw.schema !== AUTHORITY_SCHEMA || raw.subject !== subject || raw.valid !== true) fail("malformed", subject);
  if (!(["limited", "full"].includes(raw.identity_class))) fail("malformed", subject);
  if (raw.current_full_relation_satisfied !== (raw.identity_class === "full")) fail("malformed", subject);
  if (!safeProjectionEvidence(raw.evidence_source)) fail("malformed", subject);
  if (raw.observed_at !== null && !canonicalTimestamp(raw.observed_at)) fail("malformed", subject);
  if (raw.identity_class === "full" && raw.observed_at === null) fail("malformed", subject);
  return Object.freeze({ source: AUTHORITY_SOURCE, schema: AUTHORITY_SCHEMA, version: 1, subject, status: raw.identity_class, valid: true, diagnostic: "asserted", evidenceSource: raw.evidence_source, observedAt: raw.observed_at });
};

const cancel = async (response) => { try { await response?.body?.cancel?.(); } catch {} };
const responseHeader = (response, name) => response?.headers?.get?.(name);
const jsonContentType = (value) => typeof value === "string" && /^application\/json(?:[ \t]*;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*=[ \t]*(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[\t\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\t\x20-\x7e])*"))*[ \t]*$/i.test(value);

const readBody = async (response, subject) => {
  const length = responseHeader(response, "content-length");
  if (length !== null && length !== undefined && (!/^\d+$/.test(length) || Number(length) > MAX_BODY)) { await cancel(response); fail("malformed", subject); }
  const reader = response?.body?.getReader?.();
  if (!reader) { await cancel(response); fail("malformed", subject); }
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) { await reader.cancel?.(); fail("malformed", subject); }
    size += value.byteLength;
    if (size > MAX_BODY) { await reader.cancel?.(); fail("malformed", subject); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { fail("malformed", subject); }
};

const exactError = (raw, expected) => exactDataRecord(raw, ["error"]) && raw.error === expected;

export async function runAuthorityProbe(options, dependencies = {}) {
  const checked = validateOptions(options);
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies)) fail("argument", checked.subject);
  const fetchImpl = Object.hasOwn(dependencies, "fetchImpl") ? dependencies.fetchImpl : globalThis.fetch;
  const setTimer = Object.hasOwn(dependencies, "setTimeoutImpl") ? dependencies.setTimeoutImpl : globalThis.setTimeout;
  const clearTimer = Object.hasOwn(dependencies, "clearTimeoutImpl") ? dependencies.clearTimeoutImpl : globalThis.clearTimeout;
  const AbortControllerImpl = Object.hasOwn(dependencies, "AbortControllerImpl") ? dependencies.AbortControllerImpl : globalThis.AbortController;
  if (typeof fetchImpl !== "function" || typeof setTimer !== "function" || typeof clearTimer !== "function" || typeof AbortControllerImpl !== "function") fail("argument", checked.subject);

  const url = `${checked.origin}/agent/authority/current/${checked.subject}.json`;
  const controller = new AbortControllerImpl();
  let timedOut = false;
  const timer = setTimer(() => { timedOut = true; controller.abort(); }, checked.timeoutMs);
  let response;
  let succeeded = false;
  try {
    response = await fetchImpl(url, { method: "GET", redirect: "manual", credentials: "omit", headers: { Accept: "application/json" }, signal: controller.signal });
    if (!response || typeof response.status !== "number") { await cancel(response); fail("malformed", checked.subject); }
    if (response.status >= 300 && response.status < 400) { await cancel(response); fail("malformed", checked.subject); }
    if (!jsonContentType(responseHeader(response, "content-type"))) { await cancel(response); fail("malformed", checked.subject); }
    const text = await readBody(response, checked.subject);
    let raw;
    try { raw = JSON.parse(text); } catch { fail("malformed", checked.subject); }
    if (response.status === 200) { const result = validateSuccess(raw, checked.subject); succeeded = true; return result; }
    if (response.status === 404 && exactError(raw, "entitlement_denied")) fail("denied", checked.subject);
    if (response.status === 503 && exactError(raw, "entitlement_unavailable")) fail("unavailable", checked.subject);
    if (response.status === 400 && exactError(raw, "invalid_subject")) fail("invalid", checked.subject);
    fail("malformed", checked.subject);
  } catch (error) {
    if (error instanceof AuthorityProbeError) throw error;
    if (timedOut || error?.name === "AbortError") fail("unavailable", checked.subject);
    fail("unavailable", checked.subject);
  } finally {
    clearTimer(timer);
    if (!succeeded) controller.abort();
  }
}

export function formatAuthorityResult(assertion) {
  const valid = exactDataRecord(assertion, ASSERTION_FIELDS) && assertion.source === AUTHORITY_SOURCE && assertion.schema === AUTHORITY_SCHEMA && assertion.version === 1 && SUBJECT.test(assertion.subject) && assertion.valid === true && assertion.diagnostic === "asserted" && [AccessStatus.LIMITED, AccessStatus.FULL].includes(assertion.status) && safeProjectionEvidence(assertion.evidenceSource) && (assertion.observedAt === null ? assertion.status === AccessStatus.LIMITED : canonicalTimestamp(assertion.observedAt));
  if (!valid) throw new TypeError("valid canonical asserted result required");
  return Object.freeze({ output: JSON.stringify(assertion), exitCode: AUTHORITY_EXIT_CODES.asserted });
}

export function formatAuthorityFailure(error) {
  const diagnostic = error instanceof AuthorityProbeError ? error.diagnostic : "malformed";
  if (diagnostic === "asserted") throw new TypeError("asserted is not a failure");
  return Object.freeze({ output: `authority probe ${diagnostic}`, exitCode: AUTHORITY_EXIT_CODES[diagnostic] ?? AUTHORITY_EXIT_CODES.malformed });
}
