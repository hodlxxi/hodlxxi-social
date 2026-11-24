// A private phone link carries only the original pairing locator in a URL
// fragment. Fragments are not part of HTTP requests. Strip it from address
// bar/history BEFORE contacting the service; never log or persist the secret.
// This is transport of an invitation, not device authentication.
import { parsePairingQr } from "./mobile-device-authorization-contract-v1.mjs";
const deny = () => { throw new TypeError("private pairing link unavailable"); };
const canonical = value => {
  const v = parsePairingQr(value);
  return "hodlxxi-social-pair:v1:" + v.pairingId + ":" + v.secret;
};
export function makePrivatePhoneLink(locator, baseUrl) {
  try {
    if (typeof locator !== "string" || canonical(locator) !== locator) deny();
    const url = new URL(baseUrl);
    if (url.protocol !== "https:" || url.username || url.password ||
        !url.pathname.endsWith("/device-registration-v2.html") ||
        url.search || url.hash) deny();
    url.hash = "pair=" + encodeURIComponent(locator);
    return url.href;
  } catch { deny(); }
}
export function takePrivatePairingFragment(href, replaceUrl) {
  const url = new URL(href);
  if (!url.hash.startsWith("#pair=")) return null;
  // Address must be cleansed before secret parsing or any asynchronous work.
  if (typeof replaceUrl !== "function") deny();
  try {
    replaceUrl(url.pathname + url.search);
  } catch { deny(); }
  try {
    const locator = decodeURIComponent(url.hash.slice("#pair=".length));
    if (canonical(locator) !== locator) deny();
    return locator;
  } catch { deny(); }
}
