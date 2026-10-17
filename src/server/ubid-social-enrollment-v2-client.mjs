// Default-off server transport for UBID's existing V2 enrollment owners.
// Returned documents are publication evidence, never current admission.
import http from "node:http";
import { KeyObject, randomBytes, sign } from "node:crypto";
import { types } from "node:util";
import { canonicalUnixSocketPath } from "./social-oauth-config.mjs";
import { canonical, exact, parseClosedJson, hex64 } from "../../web/social-mobile-protocol-v1.mjs";

export const SOCIAL_ENROLLMENT_V2_CLIENT_ENABLED = false;
export const ENROLLMENT_PREFIX = "/internal/v2/social/enrollment";
export const ENROLLMENT_TOKEN_PATH = ENROLLMENT_PREFIX + "/service-token";
export const ENROLLMENT_SCOPES = Object.freeze(Object.fromEntries(
  ["challenge", "reserve", "finalize"].map((name) => [name, "social:enrollment-v2:" + name])
));
const VIEWER_HEADER = "X-HODLXXI-Viewer-Authorization";
const BODY_FIELDS = Object.freeze({ challenge: ["issuanceId"], reserve: ["issuanceId", "verificationInputWire"],
  finalize: ["issuanceId", "reservationId", "reservationRevision", "verificationInputWire", "evidenceCompactJws", "statementCompactJws"] });
const COMMON_FIELDS = ["schema", "version", "publicationStatus", "finalAdmission", "bearerAuthority"];
const RESULT_FIELDS = Object.freeze({ challenge: ["contextWire", "enrollmentWire", "approvalEventWire", "challengeRevision", "issuedAt", "expiresAt"],
  reserve: ["evidenceCompactJws", "reservationId", "observedAt", "expiresAt"], finalize: ["receiptWire", "historicalRecovery"] });
const MAXIMUM = 65536;
const fail = () => { throw new TypeError("social enrollment v2 unavailable"); };
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const ascii = (v, maximum) => typeof v === "string" && v.length > 0 && v.length <= maximum && /^[\x20-\x7e]+$/.test(v);
const compact = (v, maximum = 16384) => ascii(v, maximum) && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
const identifier = (v) => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(v);
const own = (v, fields) => { if (types.isProxy(v)) fail(); return exact(v, fields); };
const json = (wire, maximum) => { if (!ascii(wire, maximum)) fail(); return parseClosedJson(wire, { maximum, depth: 6 }); };
const b64 = (v) => Buffer.from(JSON.stringify(v), "ascii").toString("base64url");

function requestBody(command, value) {
  const body = own(value, BODY_FIELDS[command]);
  for (const [key, item] of Object.entries(body)) {
    if (["issuanceId", "reservationId"].includes(key)) { if (!hex64(item)) fail(); }
    else if (key === "reservationRevision") { if (item !== "1") fail(); }
    else if (key === "verificationInputWire") json(item, 24576);
    else if (!compact(item, key === "statementCompactJws" ? 4096 : 16384)) fail();
  }
  return Object.freeze(body);
}

function publication(command, source, body, at) {
  const value = own(source, [...COMMON_FIELDS, ...RESULT_FIELDS[command]]);
  if (value.schema !== "hodlxxi.social_enrollment_v2_" + command + "_publication.v1" || value.version !== 1 ||
      value.publicationStatus !== "committed" || value.finalAdmission !== "denied" || value.bearerAuthority !== "none") fail();
  if (command !== "finalize") {
    const start = command === "challenge" ? value.issuedAt : value.observedAt;
    if (!integer(start) || !integer(value.expiresAt) || !(start <= at && at < value.expiresAt) ||
        value.expiresAt - start > 60000) fail();
  }
  if (command === "challenge") {
    const context = json(value.contextWire, 4096), enrollment = json(value.enrollmentWire, 4096);
    const event = json(value.approvalEventWire, 24576);
    if (value.challengeRevision !== 1 || context.schema !== "hodlxxi.social_device_verification_context.v1" ||
        context.version !== 1 || context.challengeKind !== "enrollment-v2" || !hex64(context.challengeId) ||
        enrollment.schema !== "hodlxxi.social_messaging_device_enrollment.v2" || enrollment.version !== 2 ||
        context.challengeId !== enrollment.enrollmentChallengeId || context.subject !== enrollment.subject ||
        context.subject !== event.pubkey || !hex64(context.subject) || context.deviceId !== enrollment.deviceId ||
        context.bindingId !== enrollment.x25519BindingId || context.bindingVersion !== enrollment.x25519BindingVersion ||
        context.ed25519PublicKey !== enrollment.ed25519PublicKey || context.audience !== enrollment.audience ||
        context.x25519PublicKeyCommitment !== enrollment.x25519PublicKeyCommitment ||
        enrollment.issuedAt !== value.issuedAt || enrollment.expiresAt !== value.expiresAt) fail();
  } else if (command === "reserve") {
    if (!hex64(value.reservationId) || !compact(value.evidenceCompactJws)) fail();
  } else {
    if (typeof value.historicalRecovery !== "boolean") fail();
    const receipt = json(value.receiptWire, 4096), input = json(body.verificationInputWire, 24576);
    const context = json(input.context, 4096);
    if (receipt.schema !== "hodlxxi.social_preaccepted_enrollment_v2_acceptance_receipt.v1" || receipt.version !== 1 ||
        receipt.status !== "committed" || receipt.reservationRevision !== 1 || receipt.reservationId !== body.reservationId ||
        receipt.acceptanceId !== input.acceptanceId || receipt.challengeId !== context.challengeId ||
        receipt.associationId !== context.associationId || !hex64(receipt.receiptId) || !integer(receipt.decidedAt)) fail();
  }
  // All nested protocol objects remain primitive exact strings. They are NOT
  // a rebranded cryptographic result or a substitute for UBID/Social verifiers.
  return Object.freeze(value);
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
      reject(new TypeError("social enrollment v2 unavailable"));
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

export function createUbidSocialEnrollmentV2Client(value, dependencies) {
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
        const args = own(input, ["body", "viewerAccessToken"]), body = requestBody(command, args.body);
        if (!compact(args.viewerAccessToken) || Buffer.byteLength(canonical(body)) > MAXIMUM) fail();
        let previous = -1;
        const now = () => { const at = deps.now(); if (!integer(at) || at < previous) fail(); previous = at; return at; };
        const issuedAt = Math.floor(now() / 1000), entropy = deps.random(32);
        const assertionDeadline = (issuedAt + 60) * 1000;
        if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 32 || !integer(assertionDeadline)) fail();
        const claims = { iss: config.clientId, sub: config.clientId, aud: config.issuerOrigin + ENROLLMENT_TOKEN_PATH,
          token_use: "client_assertion", grant_type: "client_credentials", purpose: "service_client_authentication",
          iat: issuedAt, exp: issuedAt + 60, jti: Buffer.from(entropy).toString("base64url") };
        const signingInput = b64({ alg: "RS256", typ: "JWT", kid: config.clientSigningKeyId }) + "." + b64(claims);
        const assertion = signingInput + "." + sign("RSA-SHA256", Buffer.from(signingInput, "ascii"), config.signingKey).toString("base64url");
        const form = new URLSearchParams({ grant_type: "client_credentials", client_id: config.clientId,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion,
          scope: ENROLLMENT_SCOPES[command] }).toString();
        const token = own(await unixPost(config, deps.requestImpl, ENROLLMENT_TOKEN_PATH,
          { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, form, 16384),
          ["access_token", "token_type", "expires_in", "scope"]);
        if (!compact(token.access_token) || token.access_token === args.viewerAccessToken || token.token_type !== "Bearer" ||
            token.expires_in !== 60 || token.scope !== ENROLLMENT_SCOPES[command] || now() >= assertionDeadline) fail();
        const result = await unixPost(config, deps.requestImpl, ENROLLMENT_PREFIX + "/" + command,
          { Accept: "application/json", "Content-Type": "application/json", Authorization: "Bearer " + token.access_token,
            [VIEWER_HEADER]: "Bearer " + args.viewerAccessToken }, canonical(body));
        const deliveredAt = now();
        if (deliveredAt >= assertionDeadline) fail();
        return publication(command, result, body, deliveredAt);
      } catch { fail(); }
    };
    return Object.freeze(methods);
  } catch { fail(); }
}
