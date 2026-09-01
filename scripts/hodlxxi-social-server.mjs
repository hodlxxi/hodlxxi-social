#!/usr/bin/env node
import http from "node:http";
import { pathToFileURL } from "node:url";
import { configFromEnvironment } from "../src/server/social-oauth-config.mjs";
import { createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { createHodlxxiOAuthClient } from "../src/server/hodlxxi-oauth-client.mjs";
import { createSocialAuthorityReader } from "../src/server/social-authority-reader.mjs";
import { createSocialOAuthBff, parseRawRequestTarget, SECURITY_HEADERS } from "../src/server/social-oauth-bff.mjs";
import { expireTransactionCookie } from "../src/server/social-oauth-cookie.mjs";
import { createUbidFullDirectoryClient } from "../src/server/ubid-full-directory-client.mjs";
import { createUbidUnixSocketTransport } from "../src/server/ubid-unix-socket-transport.mjs";

export async function createFullDirectoryIntegration(
  fullDirectory,
  {
    transportFactory = createUbidUnixSocketTransport,
    clientFactory = createUbidFullDirectoryClient
  } = {}
) {
  if (fullDirectory?.enabled !== true) return undefined;
  const fetchImpl = transportFactory({
    socketPath: fullDirectory.socketPath,
    serviceTokenUrl: fullDirectory.serviceTokenUrl,
    directoryUrl: fullDirectory.directoryUrl
  });
  return clientFactory(fullDirectory, { fetchImpl });
}

export function classifyRequestTarget(target, publicOrigin) {
  const parsed = parseRawRequestTarget(target, publicOrigin);
  return Object.freeze({ valid: parsed.valid, callback: parsed.callback });
}

const framingProhibited = (request) => {
  const raw = request.rawHeaders ?? [];
  const lengths = [];
  let transferCount = 0;

  for (let index = 0; index < raw.length; index += 2) {
    const name = String(raw[index]).toLowerCase();

    if (name === "content-length") {
      lengths.push(String(raw[index + 1] ?? ""));
    }

    if (name === "transfer-encoding") {
      transferCount += 1;
    }
  }

  if (transferCount > 0) return true;
  if (lengths.length === 0) return false;

  // Browser POST without a body may legitimately carry Content-Length: 0.
  // Any body, duplicate length, alternate spelling, or TE remains rejected.
  return lengths.length !== 1 || lengths[0] !== "0";
};
const send = (outgoing, result) => {
  outgoing.statusCode = result.status;
  for (const [name, value] of Object.entries(result.headers)) outgoing.setHeader(name, value);
  outgoing.end(result.body);
};

export function createHttpHandler({ publicOrigin, bff }) {
  return async (incoming, outgoing) => {
    const target = classifyRequestTarget(incoming.url, publicOrigin);
    if (!target.valid || framingProhibited(incoming)) {
      const headers = { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8" };
      if (target.callback && framingProhibited(incoming)) headers["Set-Cookie"] = expireTransactionCookie();
      send(outgoing, { status: framingProhibited(incoming) ? 413 : 400, headers, body: JSON.stringify({ error: "request_rejected" }) });
      return;
    }
    const headers = {};
    for (const [name, value] of Object.entries(incoming.headers)) if (typeof value === "string") headers[name] = value;
    try { send(outgoing, await bff({ method: incoming.method, url: incoming.url, headers })); }
    catch { send(outgoing, { status: 500, headers: { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify({ error: "request_rejected" }) }); }
  };
}

export async function runServer({ env = process.env, stdout = console.log, stderr = console.error, createServer = http.createServer } = {}) {
  let config;
  try { config = configFromEnvironment(env); } catch { stderr("invalid configuration"); return 2; }
  const pendingTransactions = createBoundedStore({ ttlSeconds: config.transactionTtlSeconds, capacity: config.maxPendingTransactions });
  const sessions = createBoundedStore({ ttlSeconds: config.sessionTtlSeconds, capacity: config.maxSessions });
  const oauthClient = createHodlxxiOAuthClient(config);
  const authorityReader = createSocialAuthorityReader(config);
  let fullDirectoryClient;
  if (config.fullDirectory.enabled) {
    try {
      fullDirectoryClient = await createFullDirectoryIntegration(
        config.fullDirectory
      );
    } catch {
      stderr("invalid configuration");
      return 2;
    }
  }
  const bff = createSocialOAuthBff({
    config,
    pendingTransactions,
    sessions,
    oauthClient,
    authorityReader,
    fullDirectoryClient
  });
  const server = createServer(createHttpHandler({ publicOrigin: config.publicOrigin, bff }));
  try { await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.bindHost, resolve); }); }
  catch { stderr("listener unavailable"); return 3; }
  stdout(`listening ${config.bindHost}:${config.port}`);
  const shutdown = () => {
    server.close();
    const timer = setTimeout(() => server.closeAllConnections?.(), 5000);
    timer.unref();
  };
  process.once("SIGINT", shutdown); process.once("SIGTERM", shutdown);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) runServer().then((code) => { process.exitCode = code; });
