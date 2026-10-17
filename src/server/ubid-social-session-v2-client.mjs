// Default-off transport for genuine native V2 phone sessions; no V1 adoption.
// An active basic OAuth session is never device admission or Full authority.
import http from "node:http";
import { KeyObject, randomBytes, sign } from "node:crypto";
import { types } from "node:util";
import { canonicalUnixSocketPath } from "./social-oauth-config.mjs";
import { canonical, exact, parseClosedJson, hex64 } from "../../web/social-mobile-protocol-v1.mjs";

export const SOCIAL_NATIVE_V2_SESSION_ENABLED = false;
export const SESSION_PREFIX = "/internal/v2/social/session-issuance";
export const SESSION_TOKEN_PATH = SESSION_PREFIX + "/service-token";
export const SESSION_SCOPES = Object.freeze(Object.fromEntries(
  ["offer", "issue", "recover", "resolve", "revoke"].map((name) => [name, "social:session-issuance-v2:" + name])
));
const VIEWER_HEADER = "X-HODLXXI-Viewer-Authorization";
const PROOFS = ["operationId", "approvalWire", "secret", "possessionProof", "verifier", "deliveryKey"];
const BODY_FIELDS = Object.freeze({ offer: ["authorizationWire"], issue: PROOFS, recover: PROOFS,
  resolve: ["issuanceId"], revoke: ["issuanceId"] });
const MAXIMUM = 65536;
const fail = () => { throw new TypeError("native v2 session unavailable"); };
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const ascii = (v, maximum) => typeof v === "string" && v.length > 0 && v.length <= maximum && /^[\x20-\x7e]+$/.test(v);
const compact = (v, maximum = 16384) => ascii(v, maximum) && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
const identifier = (v) => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(v);
const own = (v, fields) => { try { if (types.isProxy(v)) fail(); return exact(v, fields); } catch { fail(); } };
const json = (wire, maximum) => { if (!ascii(wire, maximum)) fail(); return parseClosedJson(wire, { maximum, depth: 6 }); };
const b64 = (v) => Buffer.from(JSON.stringify(v), "ascii").toString("base64url");

function requestBody(command, value) {
  const body = own(value, BODY_FIELDS[command]);
  for (const [name, item] of Object.entries(body)) {
    if (name === "authorizationWire" || name === "approvalWire") json(item, 24576);
    else if (!hex64(item)) fail();
  }
  return Object.freeze(body);
}

export function validateNativeV2SessionReceipt(source) {
  const value = own(source, ["schema", "version", "issuanceId", "socialSessionIssuanceRevision", "acceptanceId", "issuedAt", "expiresAt"]);
  if (value.schema !== "hodlxxi.social_session_issuance.v2" || value.version !== 2 ||
      ![value.issuanceId, value.socialSessionIssuanceRevision, value.acceptanceId].every(hex64) ||
      !integer(value.issuedAt) || !integer(value.expiresAt) || value.issuedAt % 1000 || value.expiresAt % 1000 ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 300000) fail();
  return Object.freeze(value);
}

export function validateNativeV2SessionResponse(source, at, { resolve = false } = {}) {
  if (!integer(at) || typeof resolve !== "boolean") fail();
  const value = own(source, resolve ? ["receipt", "subject", "currentActive"] : ["receipt", "subject", "currentActive", "viewerAccessToken"]);
  value.receipt = validateNativeV2SessionReceipt(value.receipt);
  if (typeof value.currentActive !== "boolean") fail();
  if (value.currentActive) {
    if (!(value.receipt.issuedAt <= at && at < value.receipt.expiresAt) || !hex64(value.subject) ||
        !resolve && !compact(value.viewerAccessToken, 8192)) fail();
  } else if (value.subject !== null || !resolve && value.viewerAccessToken !== null) fail();
  return Object.freeze(value);
}

function publication(command, source, body, at) {
  if (command === "offer") {
    const value = own(source, ["authorizationWire"]);
    if (value.authorizationWire !== body.authorizationWire) fail();
    return Object.freeze(value);
  }
  if (command === "revoke") {
    const value = own(source, ["schema", "version", "issuanceId", "status"]);
    if (value.schema !== "hodlxxi.social_session_revocation.v2" || value.version !== 2 ||
        value.issuanceId !== body.issuanceId || value.status !== "revoked") fail();
    return Object.freeze(value);
  }
  const value = validateNativeV2SessionResponse(source, at, { resolve: command === "resolve" });
  if (command === "resolve" && value.receipt.issuanceId !== body.issuanceId) fail();
  return value;
}

function responseLength(response, maximum) {
  const raw = response?.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 || raw.length > 64) fail();
  const headers = new Map();
  for (let i = 0; i < raw.length; i += 2) {
    if (typeof raw[i] !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(raw[i]) ||
        typeof raw[i + 1] !== "string" || /[^\x20-\x7e\t]/.test(raw[i + 1])) fail();
    const name = raw[i].toLowerCase();
    if (headers.has(name)) fail();
    headers.set(name, raw[i + 1]);
  }
  if (headers.get("content-type") !== "application/json" || headers.get("cache-control") !== "no-store" ||
      headers.get("pragma") !== "no-cache" || headers.has("transfer-encoding") || headers.has("content-encoding") ||
      !/^[1-9][0-9]*$/.test(headers.get("content-length") ?? "")) fail();
  const length = Number(headers.get("content-length"));
  if (!Number.isSafeInteger(length) || length > maximum) fail();
  return length;
}

function unixPost(config, requestImpl, path, headers, body, maximum = MAXIMUM) {
  return new Promise((resolve, reject) => {
    let outgoing, incoming, finished = false;
    const timer = setTimeout(deny, config.timeoutMs);
    function deny() {
      if (finished) return;
      finished = true; clearTimeout(timer);
      try { outgoing?.destroy(); } catch {}
      try { incoming?.destroy(); } catch {}
      reject(new TypeError("native v2 session unavailable"));
    }
    try {
      outgoing = requestImpl({ socketPath: config.socketPath, path, method: "POST", setHost: false, agent: false,
        maxHeaderSize: 16384, headers: { ...headers, Host: config.host, "Content-Length": String(Buffer.byteLength(body, "utf8")) } }, (response) => {
        incoming = response;
        try {
          if (finished) { response.destroy(); return; }
          if (response.statusCode !== 200) { deny(); return; }
          const length = responseLength(response, maximum), chunks = [];
          let size = 0;
          response.on("data", (chunk) => {
            if (finished) return;
            if (!(chunk instanceof Uint8Array)) { deny(); return; }
            size += chunk.byteLength;
            if (size > length || size > maximum) { deny(); return; }
            chunks.push(Buffer.from(chunk));
          });
          response.once("error", deny); response.once("aborted", deny);
          response.once("close", () => { if (!finished) deny(); });
          response.once("end", () => {
            if (finished) return;
            try {
              if (size !== length || response.complete !== true) fail();
              const source = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
              const value = parseClosedJson(source, { maximum, depth: 6 });
              finished = true; clearTimeout(timer); resolve(value);
            } catch { deny(); }
          });
        } catch { deny(); }
      });
      if (!outgoing || typeof outgoing.once !== "function" || typeof outgoing.end !== "function" || typeof outgoing.destroy !== "function") fail();
      outgoing.once("error", deny); outgoing.once("timeout", deny); outgoing.maxHeadersCount = 32;
      outgoing.end(body);
    } catch { deny(); }
  });
}

export function createUbidSocialSessionV2Client(value, dependencies) {
  try {
    if (types.isProxy(value)) fail();
    const enabled = Object.getOwnPropertyDescriptor(value ?? {}, "enabled");
    if (enabled === undefined || Object.hasOwn(enabled, "value") && enabled.value === false) return undefined;
    if (!Object.hasOwn(enabled, "value") || enabled.value !== true) fail();
    const config = own(value, ["enabled", "issuerOrigin", "socketPath", "clientId", "clientSigningKeyId", "signingKey", "timeoutMs"]);
    const origin = new URL(config.issuerOrigin);
    if (typeof config.issuerOrigin !== "string" || origin.origin !== config.issuerOrigin || origin.protocol !== "https:" ||
        origin.username || origin.password || origin.hostname.endsWith(".") || config.issuerOrigin !== config.issuerOrigin.toLowerCase() ||
        !identifier(config.clientId) || !identifier(config.clientSigningKeyId) || !(config.signingKey instanceof KeyObject) ||
        config.signingKey.type !== "private" || config.signingKey.asymmetricKeyType !== "rsa" ||
        !Number.isSafeInteger(config.signingKey.asymmetricKeyDetails?.modulusLength) ||
        config.signingKey.asymmetricKeyDetails.modulusLength < 2048 ||
        !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 250 || config.timeoutMs > 30000) fail();
    config.socketPath = canonicalUnixSocketPath(config.socketPath); config.host = origin.host;
    Object.freeze(config);
    const deps = dependencies === undefined ? { requestImpl: http.request, now: Date.now, random: randomBytes }
      : own(dependencies, ["requestImpl", "now", "random"]);
    if (![deps.requestImpl, deps.now, deps.random].every((v) => typeof v === "function")) fail();
    const methods = {};
    for (const command of Object.keys(BODY_FIELDS)) methods[command] = async (input) => {
      try {
        const args = own(input, command === "recover" ? ["body"] : ["body", "viewerAccessToken"]);
        const body = requestBody(command, args.body);
        if (command !== "recover" && !compact(args.viewerAccessToken, 8192) || Buffer.byteLength(canonical(body)) > MAXIMUM) fail();
        let previous = -1;
        const now = () => { const at = deps.now(); if (!integer(at) || at < previous) fail(); previous = at; return at; };
        const issuedAt = Math.floor(now() / 1000), entropy = deps.random(32);
        const assertionDeadline = (issuedAt + 60) * 1000;
        if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 32 || !integer(assertionDeadline)) fail();
        const claims = { iss: config.clientId, sub: config.clientId, aud: config.issuerOrigin + SESSION_TOKEN_PATH,
          token_use: "client_assertion", grant_type: "client_credentials", purpose: "service_client_authentication",
          iat: issuedAt, exp: issuedAt + 60, jti: Buffer.from(entropy).toString("base64url") };
        const signingInput = b64({ alg: "RS256", typ: "JWT", kid: config.clientSigningKeyId }) + "." + b64(claims);
        const assertion = signingInput + "." + sign("RSA-SHA256", Buffer.from(signingInput, "ascii"), config.signingKey).toString("base64url");
        const form = new URLSearchParams({ grant_type: "client_credentials", client_id: config.clientId,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion,
          scope: SESSION_SCOPES[command] }).toString();
        const token = own(await unixPost(config, deps.requestImpl, SESSION_TOKEN_PATH,
          { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, form, 16384),
          ["access_token", "token_type", "expires_in", "scope"]);
        if (!compact(token.access_token) || token.access_token === args.viewerAccessToken || token.token_type !== "Bearer" ||
            token.expires_in !== 60 || token.scope !== SESSION_SCOPES[command] || now() >= assertionDeadline) fail();
        const result = await unixPost(config, deps.requestImpl, SESSION_PREFIX + "/" + command,
          { Accept: "application/json", "Content-Type": "application/json", Authorization: "Bearer " + token.access_token,
            ...(command === "recover" ? {} : { [VIEWER_HEADER]: "Bearer " + args.viewerAccessToken }) }, canonical(body));
        const deliveredAt = now();
        if (deliveredAt >= assertionDeadline) fail();
        const value = publication(command, result, body, deliveredAt);
        if (value.currentActive && (value.viewerAccessToken === token.access_token || value.viewerAccessToken === args.viewerAccessToken)) fail();
        return value;
      } catch { fail(); }
    };
    return Object.freeze(methods);
  } catch { fail(); }
}
