const LIMITS = Object.freeze({ port: [1, 65535], ttl: [1, 86400], capacity: [1, 10000], timeout: [100, 30000] });

const fail = () => { throw new TypeError("invalid Social OAuth configuration"); };
const text = (value, max = 512) => typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value) ? value : fail();
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

export function parseSocialOAuthConfig(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail();
  const publicOrigin = canonicalHttpsOrigin(input.publicOrigin);
  const authorityOrigin = canonicalHttpsOrigin(input.authorityOrigin);
  const bindHost = text(input.bindHost, 64);
  if (!new Set(["127.0.0.1", "::1"]).has(bindHost)) fail();
  const clientId = text(input.clientId, 256);
  text(input.clientSecret, 1024);
  const result = {
    publicOrigin, authorityOrigin, clientId, clientSecret: input.clientSecret, bindHost,
    port: integer(input.port, LIMITS.port), transactionTtlSeconds: integer(input.transactionTtlSeconds, LIMITS.ttl),
    sessionTtlSeconds: integer(input.sessionTtlSeconds, LIMITS.ttl), maxPendingTransactions: integer(input.maxPendingTransactions, LIMITS.capacity),
    maxSessions: integer(input.maxSessions, LIMITS.capacity), outboundTimeoutMs: integer(input.outboundTimeoutMs, LIMITS.timeout),
    callbackUri: `${publicOrigin}/auth/callback`, scope: "openid"
  };
  return Object.freeze(result);
}

export function configFromEnvironment(env) {
  return parseSocialOAuthConfig({ publicOrigin: env.SOCIAL_PUBLIC_ORIGIN, authorityOrigin: env.HODLXXI_AUTHORITY_ORIGIN,
    clientId: env.HODLXXI_OAUTH_CLIENT_ID, clientSecret: env.HODLXXI_OAUTH_CLIENT_SECRET, bindHost: env.SOCIAL_BIND_HOST,
    port: env.SOCIAL_PORT, transactionTtlSeconds: env.SOCIAL_TRANSACTION_TTL_SECONDS, sessionTtlSeconds: env.SOCIAL_SESSION_TTL_SECONDS,
    maxPendingTransactions: env.SOCIAL_MAX_PENDING_TRANSACTIONS, maxSessions: env.SOCIAL_MAX_SESSIONS,
    outboundTimeoutMs: env.SOCIAL_OUTBOUND_TIMEOUT_MS });
}
