// Trusted test/Phase-3 composition only. The normal CLI never imports this.
import { createSocialOAuthBff } from "./social-oauth-bff.mjs";
import { createMobileSessionManager } from "./social-mobile-session-v1.mjs";
import { createMobileBffRoutes, MOBILE_POST_ROUTES } from "./social-mobile-bff-v1.mjs";
export function createSocialMobileComposition({ enabled = false, mobileClient, issuanceClient, ...dependencies }) {
  if (enabled !== true) return Object.freeze({ bff: createSocialOAuthBff(dependencies), mobilePostRoutes: Object.freeze([]) });
  for (const [client, names] of [[mobileClient, ["qrCreate", "qrOffer", "qrScan", "qrSnapshot", "qrClaim", "qrAccept", "qrStatus", "qrClose", "legacyReserve", "legacyAccept", "legacyStatus", "legacyClose", "phoneStatus", "phoneRecover", "phoneExchange", "oauthInvalidate"]],
    [issuanceClient, ["issue", "recover", "resolve", "revoke"]]]) {
    if (!client || names.some((name) => typeof Object.getOwnPropertyDescriptor(client, name)?.value !== "function")) throw new TypeError("incomplete mobile composition");
  }
  const manager = createMobileSessionManager({ ...dependencies, mobileClient, issuanceClient });
  const mobile = createMobileBffRoutes({ ...dependencies, publicOrigin: dependencies.config.publicOrigin, manager, mobileClient, issuanceClient });
  const old = createSocialOAuthBff({ ...dependencies, sessionReader: manager.read, oauthGuard: mobile.oauthGuard });
  return Object.freeze({ bff: async (request) => await mobile.handle(request) ?? await old(request),
    mobilePostRoutes: MOBILE_POST_ROUTES, manager, capabilitySessionReader: manager.capabilityRead });
}
