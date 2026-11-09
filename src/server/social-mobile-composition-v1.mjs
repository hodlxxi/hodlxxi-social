// Trusted composition only; the runtime's separate mobile flag controls install.
import { createSocialOAuthBff } from "./social-oauth-bff.mjs";
import { createMobileSessionManager } from "./social-mobile-session-v1.mjs";
import { createMobileBffRoutes, MOBILE_POST_ROUTES } from "./social-mobile-bff-v1.mjs";
export function createSocialMobileComposition({ enabled = false, mobileClient, issuanceClient, nativeManager, ...dependencies }) {
  if (enabled !== true) return Object.freeze({ bff: createSocialOAuthBff(dependencies), mobilePostRoutes: Object.freeze([]) });
  for (const [client, names] of [[mobileClient, ["qrCreate", "qrOffer", "qrScan", "qrSnapshot", "qrClaim", "qrAccept", "qrStatus", "qrClose", "legacyReserve", "legacyAccept", "legacyStatus", "legacyClose", "phoneStatus", "phoneRecover", "phoneExchange", "oauthInvalidate"]],
    [issuanceClient, ["issue", "recover", "resolve", "revoke"]]]) {
    if (!client || names.some((name) => typeof Object.getOwnPropertyDescriptor(client, name)?.value !== "function")) throw new TypeError("incomplete mobile composition");
  }
  const manager = createMobileSessionManager({ ...dependencies, mobileClient, issuanceClient });
  const mobile = createMobileBffRoutes({ ...dependencies, publicOrigin: dependencies.config.publicOrigin, manager, mobileClient, issuanceClient });
  if (nativeManager !== undefined && ["capabilityRead", "read", "logout"].some((name) => typeof nativeManager[name] !== "function")) throw new TypeError("invalid native session manager");
  const native = (id) => dependencies.sessions.getForLogout(id)?.kind === "ubid-mobile-v2";
  const read = (id) => nativeManager && native(id) ? nativeManager.capabilityRead(id) : manager.read(id);
  const capabilityRead = (id) => nativeManager && native(id) ? nativeManager.capabilityRead(id) : manager.capabilityRead(id);
  const old = createSocialOAuthBff({ ...dependencies, sessionReader: read, oauthGuard: mobile.oauthGuard });
  return Object.freeze({ bff: async (request) => await mobile.handle(request) ?? await old(request),
    mobilePostRoutes: MOBILE_POST_ROUTES, manager, capabilitySessionReader: capabilityRead });
}
