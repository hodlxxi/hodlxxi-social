export const TRANSACTION_COOKIE_NAME = "__Host-hodlxxi-social-oauth";
export const SESSION_COOKIE_NAME = "__Host-hodlxxi-social-session";
export const MAX_COOKIE_HEADER_BYTES = 4096;

const cookieOctet = (code) => code === 0x21 || (code >= 0x23 && code <= 0x2b) || (code >= 0x2d && code <= 0x3a) || (code >= 0x3c && code <= 0x5b) || (code >= 0x5d && code <= 0x7e);
export function isCookieOctetValue(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) if (!cookieOctet(value.charCodeAt(index))) return false;
  return true;
}
const validName = (name) => typeof name === "string" && /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name);

export function serializeHostCookie(name, value, maxAge) {
  if (!name.startsWith("__Host-") || !validName(name) || !isCookieOctetValue(value) || !Number.isSafeInteger(maxAge) || maxAge < 0 || maxAge > 86400) throw new TypeError("invalid cookie");
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}
export const expireHostCookie = (name) => {
  if (!name.startsWith("__Host-") || !validName(name)) throw new TypeError("invalid cookie");
  return `${name}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`;
};
export const expireTransactionCookie = () => expireHostCookie(TRANSACTION_COOKIE_NAME);
export const expireSessionCookie = () => expireHostCookie(SESSION_COOKIE_NAME);

export function parseCookieHeader(header, sensitiveNames = [TRANSACTION_COOKIE_NAME, SESSION_COOKIE_NAME]) {
  if (header === undefined || header === null || header === "") return new Map();
  if (typeof header !== "string" || Buffer.byteLength(header, "utf8") > MAX_COOKIE_HEADER_BYTES) throw new TypeError("invalid cookie header");
  const sensitive = new Set(sensitiveNames);
  const result = new Map();
  for (const [index, rawPair] of header.split(";").entries()) {
    const pair = index === 0 ? rawPair : rawPair.replace(/^[ \t]+/, "");
    const equals = pair.indexOf("=");
    if (equals <= 0) throw new TypeError("invalid cookie header");
    const name = pair.slice(0, equals);
    const value = pair.slice(equals + 1);
    if (!validName(name) || !isCookieOctetValue(value) || result.has(name) && sensitive.has(name)) throw new TypeError("invalid cookie header");
    if (!result.has(name)) result.set(name, value);
  }
  return result;
}

export function readSecurityCookie(header, name) {
  try { return parseCookieHeader(header).get(name) ?? null; } catch { return null; }
}
