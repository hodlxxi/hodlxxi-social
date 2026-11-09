// Separate operator-selected V2 composition; ordinary server construction is V1.
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { createPublicKey, randomBytes, sign } from "node:crypto";
import { exact, parseClosedJson } from "../../web/social-mobile-protocol-v1.mjs";
import { createSessionServiceIntegration } from "./social-mobile-runtime-v1.mjs";
import { createSocialMobileComposition } from "./social-mobile-composition-v1.mjs";
import { createUbidMobileAuthorizationClient, createUbidSessionIssuanceClient } from "./ubid-social-mobile-client-v1.mjs";
import { createUbidSocialSessionV2Client } from "./ubid-social-session-v2-client.mjs";
import { createUbidSocialEnrollmentV2Client } from "./ubid-social-enrollment-v2-client.mjs";
import { createNativeV2SessionManager } from "./social-native-session-v2.mjs";
import { createEnrollmentBrowserRoutes } from "./social-enrollment-v2-bff.mjs";
import { createEnrollmentFinalizer } from "./social-enrollment-v2-finalizer.mjs";
import { createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2 as createStatementSigner }
  from "./messaging-device-preaccepted-verification-statement-v2.mjs";

const fail = () => { throw new TypeError("invalid native enrollment runtime configuration"); };
export async function readEnrollmentRuntimeManifest(path) {
  if (typeof path !== "string" || !/^\/[A-Za-z0-9_./-]+$/.test(path) || path.includes("/../") || path.includes("/./")) fail();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.uid !== 0 || info.mode & 0o027 || info.size <= 0 || info.size > 131072) fail();
    const bytes = Buffer.alloc(131073); let size = 0;
    while (size < bytes.length) {
      const value = await handle.read(bytes, size, bytes.length - size, null);
      if (!value.bytesRead) break;
      size += value.bytesRead;
    }
    if (size === 0 || size > 131072) fail();
    return parseClosedJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size)),
      { canonicalOnly: false, maximum: 131072, depth: 5 });
  } catch { fail(); }
  finally { await handle?.close(); }
}

export function enrollmentRuntimeFactory(manifest) {
  return async function createRuntime(dependencies) {
    try {
      const m = exact(manifest, ["schema", "version", "enabled", "issuerOrigin", "socialOrigin", "socketPath",
        "backendId", "clientId", "servicePrincipal", "clientSigningKeyId", "clientSigningKeyPath",
        "statementSigningKeyId", "statementSigningKeyPath", "evidenceTrust", "bindingLifetimeSeconds", "timeoutMs"]);
      const { config, sessions } = dependencies;
      if (m.schema !== "hodlxxi.social.enrollment_v2.runtime.v1" || m.version !== 1 || m.enabled !== true ||
          config.publicOrigin !== m.socialOrigin || config.authorityOrigin !== m.issuerOrigin ||
          config.clientId !== m.clientId || config.mobile.enabled !== true || config.sessionIssuance.enabled !== true ||
          !Number.isSafeInteger(m.timeoutMs) || m.timeoutMs < 250 || m.timeoutMs > 30000 ||
          !Array.isArray(m.evidenceTrust) || m.evidenceTrust.length < 1) fail();
      const integration = { enabled: true, issuerOrigin: m.issuerOrigin, socketPath: m.socketPath,
        clientId: m.backendId, clientSigningKeyId: m.clientSigningKeyId,
        signingKeyPath: m.clientSigningKeyPath, timeoutMs: m.timeoutMs };
      // Reuse the V1 file/key checks without imposing its request timeout on V2.
      // No request runs during key loading; each V2 client validates its own budget.
      const loadSigningIntegration = (keyConfig, factory) => createSessionServiceIntegration(
        { ...keyConfig, timeoutMs: 5000 },
        { clientFactory: (loaded) => factory({ ...loaded, timeoutMs: m.timeoutMs }) });
      const sessionClient = await loadSigningIntegration(integration, createUbidSocialSessionV2Client);
      const enrollmentClient = await loadSigningIntegration(integration, createUbidSocialEnrollmentV2Client);
      const statementKey = await loadSigningIntegration({ ...integration, signingKeyPath: m.statementSigningKeyPath,
        clientSigningKeyId: m.statementSigningKeyId }, (cfg) => cfg.signingKey);
      const statementSpki = createPublicKey(statementKey).export({ format: "der", type: "spki" });
      for (const trust of m.evidenceTrust) {
        exact(trust, ["publicJwk", "notBefore", "notAfter", "revokedAt"]);
        if (createPublicKey({ key: trust.publicJwk, format: "jwk" }).export({ format: "der", type: "spki" }).equals(statementSpki)) fail();
      }
      const signer = createStatementSigner({ algorithm: "RS256", audience: m.issuerOrigin + "/internal/v2/social/device-admission/consume",
        clientId: m.clientId, issuer: m.socialOrigin, kid: m.statementSigningKeyId,
        purpose: "social_preaccepted_enrollment_cryptographic_verification_v2", servicePrincipal: m.servicePrincipal,
        signExact: (bytes) => sign("RSA-SHA256", bytes, statementKey) }, { freshnessProfile: "native-v2-60s-v1" });
      const manager = createNativeV2SessionManager({ enabled: true, client: sessionClient, store: sessions,
        capacity: config.maxSessions, now: Date.now, random: randomBytes });
      const mobileClient = await createSessionServiceIntegration(config.mobile, { clientFactory: createUbidMobileAuthorizationClient });
      const issuanceClient = await createSessionServiceIntegration(config.sessionIssuance, { clientFactory: createUbidSessionIssuanceClient });
      const base = createSocialMobileComposition({ ...dependencies, enabled: true, mobileClient, issuanceClient, nativeManager: manager });
      const finalizer = createEnrollmentFinalizer({ client: enrollmentClient, signer, evidenceTrust: m.evidenceTrust,
        issuer: m.issuerOrigin, socialOrigin: m.socialOrigin, clientId: m.clientId, servicePrincipal: m.servicePrincipal });
      const enrollment = createEnrollmentBrowserRoutes({ publicOrigin: config.publicOrigin, sessions,
        desktopManager: base.manager, nativeManager: manager, sessionClient, enrollmentClient, finalizer,
        authorityReader: dependencies.authorityReader, bindingLifetimeSeconds: m.bindingLifetimeSeconds, capacity: config.maxSessions });
      return Object.freeze({ ...base, bff: async (request) => await enrollment.handle(request) ?? await base.bff(request),
        mobilePostRoutes: Object.freeze([...new Set([...base.mobilePostRoutes, ...enrollment.postRoutes])]) });
    } catch { fail(); }
  };
}
