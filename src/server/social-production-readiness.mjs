import { constants } from "node:fs";
import { access } from "node:fs/promises";
import { resolve } from "node:path";

import { configFromEnvironment } from "./social-oauth-config.mjs";

export const PRODUCTION_READINESS_SCHEMA =
  "hodlxxi.social_production_readiness.v1";

export const REQUIRED_PRODUCT_ASSETS = Object.freeze([
  "web/index.html",
  "web/auth-entry.mjs",
  "web/auth-product.mjs",
  "web/authenticated-public-read.mjs",
  "web/authenticated-public-write.mjs",
  "web/nostr-event-verifier.mjs",
  "web/components.mjs",
  "web/shell.mjs",
  "web/styles.css"
]);

const fail = () => {
  throw new TypeError("production readiness failed");
};

export async function buildSocialProductionReadiness(
  env,
  {
    cwd = process.cwd(),
    accessImpl = access
  } = {}
) {
  if (
    !env ||
    typeof env !== "object" ||
    typeof cwd !== "string" ||
    cwd.length === 0 ||
    typeof accessImpl !== "function"
  ) {
    fail();
  }

  let config;

  try {
    config = configFromEnvironment(env);
  } catch {
    fail();
  }

  // A production configuration must not collapse the Social public origin
  // into the external authority origin. This also prevents the V1.15
  // self-contained rehearsal configuration from passing as production.
  if (config.publicOrigin === config.authorityOrigin) {
    fail();
  }

  if (!config.nostrRelayUrl || !config.nostrPublishRelayUrl) {
    fail();
  }

  for (const asset of REQUIRED_PRODUCT_ASSETS) {
    try {
      await accessImpl(resolve(cwd, asset), constants.R_OK);
    } catch {
      fail();
    }
  }

  return Object.freeze({
    schema: PRODUCTION_READINESS_SCHEMA,
    version: 1,
    ready: true,
    publicOrigin: config.publicOrigin,
    authorityOrigin: config.authorityOrigin,
    callbackUri: config.callbackUri,
    bindHost: config.bindHost,
    port: config.port,
    healthPath: "/auth/health",
    staticEntrypoint: "web/index.html",
    authorityMode: "external-read-only",
    publicReadMode: "browser-one-shot-explicit-relay",
    relayHost: new URL(config.nostrRelayUrl).host,
    publicWriteMode: "browser-explicit-external-signer",
    publishRelayHost: new URL(config.nostrPublishRelayUrl).host,
    serverSigning: false,
    keyCustody: false,
    hodlxxiWrites: false,
    sessionPersistence: "process-local",
    oauthCredentials: "configured-server-side",
    networkPerformed: false,
    listenerStarted: false,
    productionWrites: false
  });
}
