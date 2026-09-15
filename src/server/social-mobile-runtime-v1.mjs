// Trusted server composition only. Browser code must never import this module.
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { createPrivateKey, KeyObject } from "node:crypto";
import { mobileServiceConfig, validateMobileRuntimeConfig } from "./social-oauth-config.mjs";
import { createUbidMobileAuthorizationClient, createUbidSessionIssuanceClient } from "./ubid-social-mobile-client-v1.mjs";
import { createSocialMobileComposition } from "./social-mobile-composition-v1.mjs";

const fail = () => { throw new TypeError("invalid mobile session configuration"); };

export async function createSessionServiceIntegration(config, {
  openFile = open,
  parseKey = createPrivateKey,
  clientFactory = createUbidSessionIssuanceClient,
  clientDependencies
} = {}) {
  if (config?.enabled !== true) return undefined;
  // Revalidate injected config before file access, including the client's
  // narrower timeout and identifier contracts. Pass no paths/PEM to the client.
  const validated = mobileServiceConfig({
    serviceEnabled: true, serviceIssuerOrigin: config.issuerOrigin,
    serviceSocketPath: config.socketPath, serviceServiceClientId: config.clientId,
    serviceServiceClientSigningKeyId: config.clientSigningKeyId,
    serviceSigningKeyPath: config.signingKeyPath, serviceTimeoutMs: config.timeoutMs
  }, "service");
  let handle;
  try {
    if (!Number.isSafeInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW <= 0) fail();
    handle = await openFile(validated.signingKeyPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size <= 0 || info.size > 16384) fail();
    // Bounded read even if a file grows after stat. Keep bytes local to loading.
    const bytes = Buffer.alloc(16385);
    let size = 0;
    try {
      while (size < bytes.length) {
        const { bytesRead } = await handle.read(bytes, size, bytes.length - size, null);
        if (bytesRead === 0) break;
        if (!Number.isSafeInteger(bytesRead) || bytesRead < 0 || bytesRead > bytes.length - size) fail();
        size += bytesRead;
      }
      if (size === 0 || size > 16384) fail();
      const signingKey = parseKey(bytes.subarray(0, size));
      if (!(signingKey instanceof KeyObject) || signingKey.type !== "private" || signingKey.asymmetricKeyType !== "rsa" ||
          !Number.isSafeInteger(signingKey.asymmetricKeyDetails?.modulusLength) || signingKey.asymmetricKeyDetails.modulusLength < 2048) fail();
      return clientFactory({
        enabled: true, issuerOrigin: validated.issuerOrigin, socketPath: validated.socketPath,
        clientId: validated.clientId, clientSigningKeyId: validated.clientSigningKeyId,
        signingKey, timeoutMs: validated.timeoutMs
      }, clientDependencies);
    } finally { bytes.fill(0); }
  } catch { fail(); }
  finally { try { await handle?.close(); } catch { fail(); } }
}

export async function createSocialMobileRuntime(dependencies, integrationDependencies = {}) {
  const { config } = dependencies;
  validateMobileRuntimeConfig(config);
  const issuanceClient = await createSessionServiceIntegration(config.sessionIssuance, integrationDependencies);
  if (config.mobile?.enabled !== true) {
    return createSocialMobileComposition({ ...dependencies, enabled: false });
  }
  if (!issuanceClient) fail();
  const mobileClient = await createSessionServiceIntegration(config.mobile, {
    ...integrationDependencies, clientFactory: createUbidMobileAuthorizationClient
  });
  return createSocialMobileComposition({ ...dependencies, enabled: true, mobileClient, issuanceClient });
}
