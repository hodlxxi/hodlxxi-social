// Separate capabilities over an explicitly supplied Unix socket. No DNS, TCP,
// environment, ambient fetch, proxy or redirect fallback. Never browser code.
import http from "node:http";
import { KeyObject, randomBytes, sign } from "node:crypto";
import { types } from "node:util";
import { canonicalUnixSocketPath } from "./social-oauth-config.mjs";
import {
  MOBILE_PREFIX, ISSUANCE_PREFIX, MOBILE_COMMANDS, ISSUANCE_COMMANDS,
  VIEWER_HEADER, MAX_MOBILE_BYTES, canonical, exact, bearer, parseClosedJson,
  validateCommand, validateMobileResponse, validateIssuanceResponse, unavailable
} from "../../web/social-mobile-protocol-v1.mjs";

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const safeName = (v) => typeof v === "string" && /^[A-Za-z0-9._:-]{1,255}$/.test(v);
const base64 = (v) => Buffer.from(JSON.stringify(v), "ascii").toString("base64url");

// Also used at trusted dependency-injection boundaries: JSON's guarantees
// must not be bypassed with accessors or Proxy-backed mock/provider objects.
export function closedServerValue(value, depth = 0) {
  if (depth > 6 || types.isProxy(value)) unavailable();
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && !Array.isArray(value)) unavailable();
    for (const [key, d] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (!Object.hasOwn(d, "value") || !d.enumerable && !(Array.isArray(value) && key === "length")) unavailable();
      closedServerValue(d.value, depth + 1);
    }
  }
  return value;
}

function configuration(value) {
  if (types.isProxy(value)) unavailable();
  const c = exact(value, ["enabled", "issuerOrigin", "socketPath", "clientId", "clientSigningKeyId", "signingKey", "timeoutMs"]);
  let origin;
  try { origin = new URL(c.issuerOrigin); } catch { unavailable(); }
  if (c.enabled !== true || typeof c.issuerOrigin !== "string" || origin.origin !== c.issuerOrigin ||
      origin.protocol !== "https:" || origin.hostname.endsWith(".") || origin.username || origin.password ||
      c.issuerOrigin !== c.issuerOrigin.toLowerCase() || !safeName(c.clientId) || !safeName(c.clientSigningKeyId) ||
      !(c.signingKey instanceof KeyObject) || c.signingKey.type !== "private" || c.signingKey.asymmetricKeyType !== "rsa" ||
      !Number.isSafeInteger(c.signingKey.asymmetricKeyDetails?.modulusLength) || c.signingKey.asymmetricKeyDetails.modulusLength < 2048 ||
      !Number.isSafeInteger(c.timeoutMs) || c.timeoutMs < 250 || c.timeoutMs > 5000) unavailable();
  c.socketPath = canonicalUnixSocketPath(c.socketPath);
  return Object.freeze({ ...c, host: origin.host });
}

function responseHeaders(incoming, maximum) {
  const raw = incoming?.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 || raw.length > 64) unavailable();
  const headers = new Map();
  for (let i = 0; i < raw.length; i += 2) {
    if (typeof raw[i] !== "string" || typeof raw[i + 1] !== "string" || /[^\x20-\x7e\t]/.test(raw[i + 1])) unavailable();
    const name = raw[i].toLowerCase();
    if (headers.has(name)) unavailable();
    headers.set(name, raw[i + 1]);
  }
  if (headers.get("content-type") !== "application/json" || headers.get("cache-control") !== "no-store" ||
      headers.get("pragma") !== "no-cache" || headers.has("content-encoding") || headers.has("transfer-encoding") ||
      !/^[1-9][0-9]*$/.test(headers.get("content-length") ?? "")) unavailable();
  const length = Number(headers.get("content-length"));
  if (!Number.isSafeInteger(length) || length > maximum) unavailable();
  return length;
}

function unixPost(config, requestImpl, path, headers, body, maximum) {
  return new Promise((resolve, reject) => {
    let outgoing, incoming, finished = false;
    const timer = setTimeout(() => fail(), config.timeoutMs);
    function fail() {
      if (finished) return;
      finished = true; clearTimeout(timer);
      try { outgoing?.destroy(); } catch {}
      try { incoming?.destroy(); } catch {}
      reject(new Error("mobile authorization unavailable"));
    }
    try {
      outgoing = requestImpl({ socketPath: config.socketPath, method: "POST", path,
        headers: { ...headers, Host: config.host, "Content-Length": String(Buffer.byteLength(body, "utf8")) },
        setHost: false, maxHeaderSize: 16384, agent: false }, (response) => {
        incoming = response;
        try {
          if (finished) { response.destroy(); return; }
          if (response.statusCode !== 200) { fail(); return; }
          const declared = responseHeaders(response, maximum);
          const chunks = [];
          let size = 0;
          response.on("data", (chunk) => {
            if (finished) return;
            if (!(chunk instanceof Uint8Array)) { fail(); return; }
            size += chunk.byteLength;
            if (size > declared || size > maximum) { fail(); return; }
            chunks.push(Buffer.from(chunk));
          });
          response.once("error", fail);
          response.once("aborted", fail);
          response.once("close", () => { if (!finished) fail(); });
          response.once("end", () => {
            if (finished) return;
            try {
              if (size !== declared || response.complete !== true) unavailable();
              const source = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
              const value = parseClosedJson(source, { maximum });
              finished = true; clearTimeout(timer); resolve(value);
            } catch { fail(); }
          });
        } catch { fail(); }
      });
      if (!outgoing || typeof outgoing.once !== "function" || typeof outgoing.end !== "function") unavailable();
      outgoing.once("error", fail);
      outgoing.once("timeout", fail);
      outgoing.maxHeadersCount = 32;
      outgoing.end(body);
    } catch { fail(); }
  });
}

function client(value, issuance, dependencies) {
  // Disabled construction never reads a key or touches a transport.
  if (types.isProxy(value)) unavailable();
  if (Object.getOwnPropertyDescriptor(value ?? {}, "enabled")?.value !== true) return undefined;
  const config = configuration(value);
  if (types.isProxy(dependencies)) unavailable();
  const { requestImpl = http.request, now = Date.now, random = randomBytes } = dependencies ?? {};
  if (![requestImpl, now, random].every((v) => typeof v === "function")) unavailable();
  const prefix = issuance ? ISSUANCE_PREFIX : MOBILE_PREFIX;
  const specs = issuance ? ISSUANCE_COMMANDS : MOBILE_COMMANDS;
  const tokenPath = prefix + "/service-token";
  const scope = (group) => issuance ? "social:session-issuance:manage" : "social:mobile-authorization:" + group;

  async function serviceToken(group) {
    const time = Math.floor(now() / 1000), entropy = random(32);
    if (!Number.isSafeInteger(time) || time < 0 || !(entropy instanceof Uint8Array) || entropy.byteLength !== 32) unavailable();
    const header = { alg: "RS256", typ: "JWT", kid: config.clientSigningKeyId };
    const claims = { iss: config.clientId, sub: config.clientId, aud: config.issuerOrigin + tokenPath,
      token_use: "client_assertion", grant_type: "client_credentials", purpose: "service_client_authentication",
      iat: time, exp: time + 60, jti: Buffer.from(entropy).toString("base64url") };
    const input = base64(header) + "." + base64(claims);
    const assertion = input + "." + sign("RSA-SHA256", Buffer.from(input, "ascii"), config.signingKey).toString("base64url");
    const body = new URLSearchParams({ grant_type: "client_credentials", client_id: config.clientId,
      client_assertion_type: ASSERTION_TYPE, client_assertion: assertion, scope: scope(group) }).toString();
    const result = exact(await unixPost(config, requestImpl, tokenPath,
      { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, body, 16384),
    ["access_token", "token_type", "expires_in", "scope"]);
    if (!bearer(result.access_token) || result.token_type !== "Bearer" || result.expires_in !== 60 || result.scope !== scope(group)) unavailable();
    return result.access_token;
  }

  const methods = {};
  for (const [name, spec] of Object.entries(specs)) {
    const viewerRequired = issuance ? ["resolve", "revoke"].includes(name) : ["desktop", "invalidate"].includes(spec.group);
    // Paths/credential groups are closed over here, never selected from a URL or
    // browser action field. Each exported method has one fixed upstream target.
    methods[name] = async (input) => {
      try {
        if (types.isProxy(input)) unavailable();
        const args = exact(input, viewerRequired ? ["body", "viewerAccessToken"] : ["body"]);
        if (types.isProxy(args.body)) unavailable();
        const body = canonical(validateCommand(spec, args.body));
        if (Buffer.byteLength(body) > MAX_MOBILE_BYTES || viewerRequired && !bearer(args.viewerAccessToken)) unavailable();
        const token = await serviceToken(spec.group);
        if (token === args.viewerAccessToken) unavailable();
        const headers = { Accept: "application/json", "Content-Type": "application/json", Authorization: "Bearer " + token };
        if (viewerRequired) headers[VIEWER_HEADER] = "Bearer " + args.viewerAccessToken;
        const result = await unixPost(config, requestImpl, prefix + "/" + spec.path, headers, body, MAX_MOBILE_BYTES);
        return issuance ? validateIssuanceResponse(name, result) : validateMobileResponse(name, result);
      } catch { unavailable(); }
    };
  }
  return Object.freeze(methods);
}

export const createUbidMobileAuthorizationClient = (config, dependencies) => client(config, false, dependencies);
export const createUbidSessionIssuanceClient = (config, dependencies) => client(config, true, dependencies);
