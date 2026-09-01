import { isAbsolute, posix } from "node:path";

const LIMITS = Object.freeze({ port: [1, 65535], ttl: [1, 86400], capacity: [1, 10000], timeout: [250, 30000] });

const fail = () => { throw new TypeError("invalid Social OAuth configuration"); };
const text = (value, max = 512) => typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value) ? value : fail();
const exactCredentialString = (value, maximum) => {
  const parsed = text(value, maximum);
  if (parsed.trim() !== parsed) fail();
  return parsed;
};
const integer = (value, [minimum, maximum]) => {
  if ((typeof value !== "string" && typeof value !== "number") || !/^[0-9]+$/.test(String(value))) fail();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) fail();
  return parsed;
};

export function canonicalHttpsOrigin(value) {
  const raw = text(value, 2048);
  let url;
  try { url = new URL(raw); } catch { fail(); }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.origin !== raw || url.hostname.endsWith(".")) fail();
  return url.origin;
}

export function canonicalWssRelayUrl(value) {
  const raw = text(value, 2048);
  let url;
  try { url = new URL(raw); } catch { fail(); }
  if (
    url.protocol !== "wss:" ||
    !url.hostname ||
    url.hostname.endsWith(".") ||
    url.username ||
    url.password ||
    url.hash
  ) fail();
  return url.href;
}

export function canonicalHttpsUrl(value) {
  const raw = text(value, 2048);
  let url;
  try { url = new URL(raw); } catch { fail(); }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.hostname.endsWith(".") ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.href !== raw
  ) fail();
  return url.href;
}

const fullDirectoryEnabled = (value) => {
  if ([undefined, null, "", false, "false"].includes(value)) return false;
  if ([true, "true"].includes(value)) return true;
  fail();
};

const MAX_UNIX_SOCKET_PATH_BYTES = 107;

export function canonicalUnixSocketPath(value) {
  const raw = text(value, MAX_UNIX_SOCKET_PATH_BYTES);
  const segments = raw.split("/");
  if (
    !posix.isAbsolute(raw) ||
    raw === "/" ||
    raw.endsWith("/") ||
    Buffer.byteLength(raw, "utf8") > MAX_UNIX_SOCKET_PATH_BYTES ||
    posix.normalize(raw) !== raw ||
    !/^[A-Za-z0-9._/-]+$/.test(raw) ||
    segments.slice(1).some((segment) =>
      segment.length === 0 || segment === "." || segment === ".."
    )
  ) fail();
  return raw;
}

const fullDirectoryConfig = (input) => {
  if (!fullDirectoryEnabled(input.fullDirectoryEnabled)) {
    return Object.freeze({ enabled: false });
  }

  const socketPath = canonicalUnixSocketPath(input.fullDirectorySocketPath);
  const signingKeyPath = text(input.fullDirectorySigningKeyPath, 2048);
  if (!isAbsolute(signingKeyPath)) fail();

  return Object.freeze({
    enabled: true,
    socketPath,
    serviceTokenUrl: canonicalHttpsUrl(input.fullDirectoryServiceTokenUrl),
    directoryUrl: canonicalHttpsUrl(input.fullDirectoryUrl),
    clientId: exactCredentialString(
      input.fullDirectoryServiceClientId,
      256
    ),
    clientSigningKeyId: exactCredentialString(
      input.fullDirectoryServiceClientSigningKeyId,
      255
    ),
    tokenEndpointAudience: exactCredentialString(
      input.fullDirectoryServiceTokenEndpointAudience,
      2048
    ),
    signingKeyPath,
    tokenTimeoutMs: integer(input.fullDirectoryTokenTimeoutMs, LIMITS.timeout),
    requestTimeoutMs: integer(input.fullDirectoryRequestTimeoutMs, LIMITS.timeout)
  });
};

export function parseSocialOAuthConfig(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail();
  const publicOrigin = canonicalHttpsOrigin(input.publicOrigin);
  const authorityOrigin = canonicalHttpsOrigin(input.authorityOrigin);
  const bindHost = text(input.bindHost, 64);
  if (!new Set(["127.0.0.1", "::1"]).has(bindHost)) fail();
  const clientId = text(input.clientId, 256);
  text(input.clientSecret, 1024);
  const nostrRelayUrl = [undefined, null, ""].includes(input.nostrRelayUrl)
    ? null
    : canonicalWssRelayUrl(input.nostrRelayUrl);
  const nostrPublishRelayUrl = [undefined, null, ""].includes(input.nostrPublishRelayUrl)
    ? null
    : canonicalWssRelayUrl(input.nostrPublishRelayUrl);
  const result = {
    publicOrigin, authorityOrigin, clientId, clientSecret: input.clientSecret, bindHost, nostrRelayUrl, nostrPublishRelayUrl,
    port: integer(input.port, LIMITS.port), transactionTtlSeconds: integer(input.transactionTtlSeconds, LIMITS.ttl),
    sessionTtlSeconds: integer(input.sessionTtlSeconds, LIMITS.ttl), maxPendingTransactions: integer(input.maxPendingTransactions, LIMITS.capacity),
    maxSessions: integer(input.maxSessions, LIMITS.capacity), outboundTimeoutMs: integer(input.outboundTimeoutMs, LIMITS.timeout),
    callbackUri: `${publicOrigin}/auth/callback`, scope: "openid",
    fullDirectory: fullDirectoryConfig(input)
  };
  return Object.freeze(result);
}

export function configFromEnvironment(env) {
  return parseSocialOAuthConfig({ publicOrigin: env.SOCIAL_PUBLIC_ORIGIN, authorityOrigin: env.HODLXXI_AUTHORITY_ORIGIN,
    clientId: env.HODLXXI_OAUTH_CLIENT_ID, clientSecret: env.HODLXXI_OAUTH_CLIENT_SECRET, bindHost: env.SOCIAL_BIND_HOST,
    port: env.SOCIAL_PORT, transactionTtlSeconds: env.SOCIAL_TRANSACTION_TTL_SECONDS, sessionTtlSeconds: env.SOCIAL_SESSION_TTL_SECONDS,
    maxPendingTransactions: env.SOCIAL_MAX_PENDING_TRANSACTIONS, maxSessions: env.SOCIAL_MAX_SESSIONS,
    outboundTimeoutMs: env.SOCIAL_OUTBOUND_TIMEOUT_MS, nostrRelayUrl: env.SOCIAL_NOSTR_RELAY_URL,
    nostrPublishRelayUrl: env.SOCIAL_NOSTR_PUBLISH_RELAY_URL,
    fullDirectoryEnabled: env.SOCIAL_FULL_DIRECTORY_ENABLED,
    fullDirectorySocketPath: env.SOCIAL_UBID_PRIVATE_SOCKET_PATH,
    fullDirectoryServiceTokenUrl: env.SOCIAL_UBID_SERVICE_TOKEN_URL,
    fullDirectoryUrl: env.SOCIAL_UBID_FULL_DIRECTORY_URL,
    fullDirectoryServiceClientId: env.SOCIAL_UBID_SERVICE_CLIENT_ID,
    fullDirectoryServiceClientSigningKeyId:
      env.SOCIAL_UBID_SERVICE_CLIENT_SIGNING_KEY_ID,
    fullDirectoryServiceTokenEndpointAudience:
      env.SOCIAL_UBID_SERVICE_TOKEN_ENDPOINT_AUDIENCE,
    fullDirectorySigningKeyPath: env.SOCIAL_UBID_SERVICE_SIGNING_KEY_PATH,
    fullDirectoryTokenTimeoutMs: env.SOCIAL_UBID_SERVICE_TOKEN_TIMEOUT_MS,
    fullDirectoryRequestTimeoutMs: env.SOCIAL_UBID_FULL_DIRECTORY_TIMEOUT_MS });
}
