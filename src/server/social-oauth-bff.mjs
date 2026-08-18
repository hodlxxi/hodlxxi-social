import { randomBytes } from "node:crypto";
import { createPkceChallenge, createPkceVerifier, base64url } from "./hodlxxi-oauth-client.mjs";
import { TRANSACTION_COOKIE_NAME, SESSION_COOKIE_NAME, parseCookieHeader, serializeHostCookie, expireTransactionCookie, expireSessionCookie } from "./social-oauth-cookie.mjs";

export const SECURITY_HEADERS = Object.freeze({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" });
const MAX_REQUEST_TARGET_BYTES = 4096;
const INVALID_REQUEST_TARGET = Object.freeze({ valid: false, callback: false });
const RAW_QUERY_COMPONENT = /^(?:[A-Za-z0-9.*_~-]|%[0-9A-Fa-f]{2})*$/;
const DECODED_CONTROL_OR_WHITESPACE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}]/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const response = (status, body, headers = {}) => Object.freeze({ status, headers: Object.freeze({ ...SECURITY_HEADERS, ...headers }), body });
const json = (status, body, headers) => response(status, JSON.stringify(body), { "Content-Type": "application/json; charset=utf-8", ...headers });
const error = (status = 400, headers) => json(status, { error: "request_rejected" }, headers);
const randomId = (random) => base64url(random(32));
const SUBJECT = /^[0-9a-f]{64}$/;
const AUTHORITY_FIELDS = Object.freeze(["status", "subject", "valid"]);

const failClosedAuthority = (subject) =>
  Object.freeze({ subject, status: "limited", valid: false });

const normalizeAuthorityProjection = (subject, value) => {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return failClosedAuthority(subject);
  }

  const keys = Reflect.ownKeys(value);

  if (
    keys.length !== AUTHORITY_FIELDS.length ||
    keys.some((key) => typeof key !== "string") ||
    AUTHORITY_FIELDS.some((field) => !keys.includes(field))
  ) {
    return failClosedAuthority(subject);
  }

  const extracted = Object.create(null);

  for (const field of AUTHORITY_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);

    if (
      !descriptor?.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      return failClosedAuthority(subject);
    }

    extracted[field] = descriptor.value;
  }

  if (
    extracted.subject !== subject ||
    !SUBJECT.test(extracted.subject)
  ) {
    return failClosedAuthority(subject);
  }

  if (
    extracted.valid === true &&
    ["limited", "full"].includes(extracted.status)
  ) {
    return Object.freeze({
      subject,
      status: extracted.status,
      valid: true
    });
  }

  if (
    extracted.valid === false &&
    extracted.status === "limited"
  ) {
    return failClosedAuthority(subject);
  }

  return failClosedAuthority(subject);
};

const invalidRequestTarget = () => INVALID_REQUEST_TARGET;
const decodeQueryComponent = (raw) => {
  if (!RAW_QUERY_COMPONENT.test(raw)) return null;
  const bytes = [];
  for (let offset = 0; offset < raw.length; offset += 1) {
    if (raw[offset] === "%") {
      bytes.push(Number.parseInt(raw.slice(offset + 1, offset + 3), 16));
      offset += 2;
    } else bytes.push(raw.charCodeAt(offset));
  }
  try {
    const decoded = UTF8_DECODER.decode(Uint8Array.from(bytes));
    return DECODED_CONTROL_OR_WHITESPACE.test(decoded) ? null : decoded;
  } catch { return null; }
};

export function parseRawRequestTarget(target, publicOrigin) {
  if (typeof target !== "string" || target.length === 0 || Buffer.byteLength(target) > MAX_REQUEST_TARGET_BYTES || /[^\x21-\x7e]/.test(target) || target.includes("#")) return invalidRequestTarget();
  let originForm;
  if (target.startsWith("/")) {
    if (target.startsWith("//")) return invalidRequestTarget();
    originForm = target;
  } else if (typeof publicOrigin === "string" && target === publicOrigin) originForm = "/";
  else {
    const schemeOffset = target.indexOf("://"), pathOffset = schemeOffset < 1 ? -1 : target.indexOf("/", schemeOffset + 3);
    if (typeof publicOrigin !== "string" || pathOffset === -1 || target.slice(0, pathOffset) !== publicOrigin) return invalidRequestTarget();
    originForm = target.slice(pathOffset);
  }

  const queryOffset = originForm.indexOf("?");
  const rawPath = queryOffset === -1 ? originForm : originForm.slice(0, queryOffset);
  if (!rawPath.startsWith("/") || rawPath.includes("%") || rawPath.includes("\\")) return invalidRequestTarget();
  if (rawPath !== "/") {
    const segments = rawPath.slice(1).split("/");
    if (segments.some((segment) => segment.length === 0 || segment === "." || segment === ".." || !/^[A-Za-z0-9._~!$&'()*+,;=:@-]+$/.test(segment))) return invalidRequestTarget();
  }

  const query = [];
  if (queryOffset !== -1) {
    const rawQuery = originForm.slice(queryOffset + 1);
    if (rawQuery.length === 0) return invalidRequestTarget();
    for (const component of rawQuery.split("&")) {
      if (component.length === 0) return invalidRequestTarget();
      const equalsOffset = component.indexOf("=");
      if (equalsOffset < 1) return invalidRequestTarget();
      const rawName = component.slice(0, equalsOffset), rawValue = component.slice(equalsOffset + 1);
      const name = decodeQueryComponent(rawName), value = decodeQueryComponent(rawValue);
      if (name === null || name.length === 0 || value === null) return invalidRequestTarget();
      query.push(Object.freeze([name, value]));
    }
  }
  return Object.freeze({ valid: true, callback: rawPath === "/auth/callback", path: rawPath, query: Object.freeze(query) });
}

const exactQuery = (entries, names) => {
  if (entries.length !== names.length) return null;
  const values = Object.create(null);
  for (const [name, value] of entries) {
    if (!names.includes(name) || name.includes("[") || name.includes("]") || value.length === 0 || Object.hasOwn(values, name)) return null;
    values[name] = value;
  }
  return names.every((name) => Object.hasOwn(values, name)) ? Object.freeze(values) : null;
};

export function createSocialOAuthBff({ config, pendingTransactions, sessions, oauthClient, authorityReader, random = randomBytes }) {
  if (
    ![pendingTransactions, sessions, oauthClient].every(Boolean) ||
    typeof random !== "function" ||
    (
      authorityReader !== undefined &&
      typeof authorityReader !== "function"
    )
  ) {
    throw new TypeError("invalid BFF dependencies");
  }
  const callbackHeaders = (extra = {}) => ({ "Set-Cookie": expireTransactionCookie(), ...extra });
  return async function handle(request) {
    const method = request.method;
    const target = parseRawRequestTarget(request.url, config.publicOrigin);
    if (!target.valid) return error();
    const cookieHeader = request.headers?.cookie;
    if (target.path === "/auth/login") {
      if (method !== "GET" || target.query.length !== 0) return error(method === "GET" ? 400 : 405);
      const state = randomId(random), transactionId = randomId(random), verifier = createPkceVerifier(random);
      if (!pendingTransactions.create(transactionId, { state, verifier })) return error(503);
      const authorize = new URL("/oauth/authorize", config.authorityOrigin);
      for (const [name, value] of Object.entries({ response_type: "code", client_id: config.clientId, redirect_uri: config.callbackUri,
        scope: config.scope, state, code_challenge: createPkceChallenge(verifier), code_challenge_method: "S256" })) authorize.searchParams.set(name, value);
      return response(302, "", { Location: authorize.href, "Set-Cookie": serializeHostCookie(TRANSACTION_COOKIE_NAME, transactionId, config.transactionTtlSeconds) });
    }
    if (target.callback) {
      const terminal = (status = 400) => error(status, callbackHeaders());
      if (method !== "GET") return terminal(405);
      const query = exactQuery(target.query, ["code", "state"]); if (!query) return terminal();
      let transactionId; try { transactionId = parseCookieHeader(cookieHeader).get(TRANSACTION_COOKIE_NAME); } catch { return terminal(); }
      if (!transactionId) return terminal();
      const transaction = pendingTransactions.consumeIf(transactionId, (candidate) => candidate.state === query.state);
      if (!transaction) return terminal();
      try {
        const subject = await oauthClient.authenticate({ code: query.code, verifier: transaction.verifier });
        let sessionId; for (let attempt = 0; attempt < 4; attempt += 1) { sessionId = randomId(random); if (sessions.create(sessionId, { subject })) break; sessionId = null; }
        if (!sessionId) return terminal(503);
        return response(303, "", callbackHeaders({ Location: "/", "Set-Cookie": [expireTransactionCookie(), serializeHostCookie(SESSION_COOKIE_NAME, sessionId, config.sessionTtlSeconds)] }));
      } catch { return terminal(502); }
    }
    if (target.path === "/auth/session") {
      if (method !== "GET" || target.query.length !== 0) return error(method === "GET" ? 400 : 405);
      let id; try { id = parseCookieHeader(cookieHeader).get(SESSION_COOKIE_NAME); } catch { return json(200, { authenticated: false }); }
      const session = id ? sessions.get(id) : null;
      return json(200, session ? { authenticated: true, subject: session.subject } : { authenticated: false });
    }
    if (target.path === "/auth/authority") {
      if (method !== "GET" || target.query.length !== 0) {
        return error(method === "GET" ? 400 : 405);
      }

      let id;

      try {
        id = parseCookieHeader(cookieHeader).get(SESSION_COOKIE_NAME);
      } catch {
        return json(401, { error: "authentication_required" });
      }

      const session = id ? sessions.get(id) : null;

      if (
        !session ||
        typeof session.subject !== "string" ||
        !SUBJECT.test(session.subject)
      ) {
        return json(401, { error: "authentication_required" });
      }

      let projection = failClosedAuthority(session.subject);

      if (authorityReader) {
        try {
          projection = normalizeAuthorityProjection(
            session.subject,
            await authorityReader(session.subject)
          );
        } catch {
          projection = failClosedAuthority(session.subject);
        }
      }

      return json(200, projection);
    }

    if (target.path === "/auth/logout") {
      if (method !== "POST") return error(405);
      if (request.headers?.origin !== config.publicOrigin || target.query.length !== 0) return error(403);
      try { const id = parseCookieHeader(cookieHeader).get(SESSION_COOKIE_NAME); if (id) sessions.delete(id); } catch { /* still expire */ }
      return json(200, { authenticated: false }, { "Set-Cookie": expireSessionCookie() });
    }
    return error(404);
  };
}
