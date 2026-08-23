#!/usr/bin/env node

import https from "node:https";
import { readFile } from "node:fs/promises";
import { isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseSocialOAuthConfig } from "../src/server/social-oauth-config.mjs";
import { createBoundedStore } from "../src/server/social-oauth-memory.mjs";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs";
import { createHttpHandler } from "./hodlxxi-social-server.mjs";

export const REHEARSAL_SUBJECT = "f".repeat(64);
export const REHEARSAL_CODE = "hodlxxi-social-rehearsal-code";

const WEB_ROOT = fileURLToPath(new URL("../web/", import.meta.url));
const STATUS = new Set(["limited", "full"]);
const VERIFIER = /^[A-Za-z0-9_-]{43}$/;
const AUTHENTICATED_ASSET_REVISION = "1.19.0";
const REVISIONED_AUTHENTICATED_ASSETS = new Set([
  "/styles.css",
  "/auth-entry.mjs",
  "/auth-product.mjs",
  "/authenticated-public-read.mjs",
  "/nostr-event-verifier.mjs",
  "/components.mjs",
  "/shell.mjs"
]);

const securityHeaders = Object.freeze({
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-HODLXXI-Rehearsal": "local-only"
});

const wire = (status, body = "", headers = {}) =>
  Object.freeze({
    status,
    body,
    headers: Object.freeze({ ...securityHeaders, ...headers })
  });

const send = (outgoing, result, head = false) => {
  outgoing.statusCode = result.status;
  for (const [name, value] of Object.entries(result.headers)) {
    outgoing.setHeader(name, value);
  }
  outgoing.end(head ? "" : result.body);
};

const optionText = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 2048 &&
  !/[\u0000-\u001f\u007f]/.test(value)
    ? value
    : null;

export function parseRehearsalOptions(env = {}) {
  const rawPort = env.SOCIAL_REHEARSAL_PORT ?? "8443";
  if (!/^[0-9]+$/.test(rawPort)) throw new TypeError("invalid rehearsal configuration");

  const port = Number(rawPort);
  const status = env.SOCIAL_REHEARSAL_STATUS ?? "limited";
  const keyPath = optionText(env.SOCIAL_REHEARSAL_KEY);
  const certPath = optionText(env.SOCIAL_REHEARSAL_CERT);

  if (
    !Number.isSafeInteger(port) ||
    port < 1024 ||
    port > 65535 ||
    !STATUS.has(status) ||
    !keyPath ||
    !certPath ||
    !isAbsolute(keyPath) ||
    !isAbsolute(certPath)
  ) {
    throw new TypeError("invalid rehearsal configuration");
  }

  return Object.freeze({ port, status, keyPath, certPath });
}

export function createRehearsalRuntime({
  port = 8443,
  status = "limited",
  random
} = {}) {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535 || !STATUS.has(status)) {
    throw new TypeError("invalid rehearsal runtime");
  }

  const publicOrigin = `https://127.0.0.1:${port}`;

  const config = parseSocialOAuthConfig({
    publicOrigin,
    authorityOrigin: publicOrigin,
    clientId: "hodlxxi-social-local-rehearsal",
    clientSecret: "local-rehearsal-only",
    bindHost: "127.0.0.1",
    port,
    transactionTtlSeconds: 300,
    sessionTtlSeconds: 1800,
    maxPendingTransactions: 32,
    maxSessions: 32,
    outboundTimeoutMs: 1000
  });

  const pendingTransactions = createBoundedStore({
    ttlSeconds: config.transactionTtlSeconds,
    capacity: config.maxPendingTransactions
  });

  const sessions = createBoundedStore({
    ttlSeconds: config.sessionTtlSeconds,
    capacity: config.maxSessions
  });

  const oauthClient = Object.freeze({
    async authenticate({ code, verifier }) {
      if (code !== REHEARSAL_CODE || typeof verifier !== "string" || !VERIFIER.test(verifier)) {
        throw new Error("rehearsal authentication rejected");
      }
      return REHEARSAL_SUBJECT;
    }
  });

  const authorityReader = async (subject) =>
    subject === REHEARSAL_SUBJECT
      ? Object.freeze({ subject, status, valid: true })
      : Object.freeze({ subject, status: "limited", valid: false });

  const bff = createSocialOAuthBff({
    config,
    pendingTransactions,
    sessions,
    oauthClient,
    authorityReader,
    ...(random ? { random } : {})
  });

  const authHandler = createHttpHandler({
    publicOrigin: config.publicOrigin,
    bff
  });

  const authorize = (target) => {
    let url;
    try {
      url = new URL(target, config.publicOrigin);
    } catch {
      return wire(400);
    }

    const expected = [
      "response_type",
      "client_id",
      "redirect_uri",
      "scope",
      "state",
      "code_challenge",
      "code_challenge_method"
    ];

    if (
      url.origin !== config.publicOrigin ||
      url.pathname !== "/oauth/authorize" ||
      url.hash ||
      [...url.searchParams.keys()].length !== expected.length ||
      expected.some((name) => url.searchParams.getAll(name).length !== 1) ||
      [...url.searchParams.keys()].some((name) => !expected.includes(name)) ||
      url.searchParams.get("response_type") !== "code" ||
      url.searchParams.get("client_id") !== config.clientId ||
      url.searchParams.get("redirect_uri") !== config.callbackUri ||
      url.searchParams.get("scope") !== config.scope ||
      url.searchParams.get("code_challenge_method") !== "S256"
    ) {
      return wire(400);
    }

    const state = url.searchParams.get("state");
    const challenge = url.searchParams.get("code_challenge");

    if (
      !state ||
      state.length > 128 ||
      !/^[A-Za-z0-9_-]+$/.test(state) ||
      !challenge ||
      !VERIFIER.test(challenge)
    ) {
      return wire(400);
    }

    const callback = new URL("/auth/callback", config.publicOrigin);
    callback.searchParams.set("code", REHEARSAL_CODE);
    callback.searchParams.set("state", state);

    return wire(302, "", { Location: `${callback.pathname}${callback.search}` });
  };

  return Object.freeze({ config, bff, authHandler, authorize, status });
}

const staticPath = (target) => {
  if (
    typeof target !== "string" ||
    !target.startsWith("/") ||
    target.startsWith("//") ||
    target.includes("#") ||
    target.includes("%") ||
    target.includes("\\")
  ) {
    return null;
  }

  const queryOffset = target.indexOf("?");
  const rawPath = queryOffset < 0
    ? target
    : target.slice(0, queryOffset);
  const query = queryOffset < 0
    ? ""
    : target.slice(queryOffset + 1);
  const pathname = rawPath === "/" ? "/index.html" : rawPath;

  if (
    query &&
    (
      query !== `v=${AUTHENTICATED_ASSET_REVISION}` ||
      !REVISIONED_AUTHENTICATED_ASSETS.has(pathname)
    )
  ) {
    return null;
  }

  if (queryOffset >= 0 && query.length === 0) {
    return null;
  }

  const segments = pathname.slice(1).split("/");

  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    return null;
  }

  return pathname;
};

const contentType = (pathname) => {
  if (pathname.endsWith(".html")) return "text/html; charset=utf-8";
  if (pathname.endsWith(".mjs")) return "text/javascript; charset=utf-8";
  if (pathname.endsWith(".css")) return "text/css; charset=utf-8";
  if (pathname.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
};

const rehearsalBanner = (html, status) =>
  html.replace(
    "<body>",
    `<body><div style="padding:10px 16px;background:#111;color:#fff;text-align:center;font:600 13px system-ui">LOCAL V1.15 REHEARSAL · synthetic OAuth identity · synthetic ${status.toUpperCase()} authority · no production writes</div>`
  );

export function createRehearsalHandler({
  runtime,
  webRoot = WEB_ROOT,
  readFileImpl = readFile
}) {
  if (!runtime?.config || typeof runtime.authHandler !== "function" || typeof runtime.authorize !== "function") {
    throw new TypeError("invalid rehearsal handler");
  }

  const root = resolve(webRoot);

  return async (incoming, outgoing) => {
    const target = incoming.url ?? "";

    if (target.startsWith("/auth/")) {
      await runtime.authHandler(incoming, outgoing);
      return;
    }

    if (target.startsWith("/oauth/authorize")) {
      if (incoming.method !== "GET") {
        send(outgoing, wire(405));
        return;
      }
      send(outgoing, runtime.authorize(target));
      return;
    }

    if (!["GET", "HEAD"].includes(incoming.method)) {
      send(outgoing, wire(405));
      return;
    }

    const pathname = staticPath(target);
    if (!pathname) {
      send(outgoing, wire(400));
      return;
    }

    const filename = resolve(root, `.${pathname}`);
    if (filename !== root && !filename.startsWith(`${root}${sep}`)) {
      send(outgoing, wire(400));
      return;
    }

    try {
      let body = await readFileImpl(filename);
      if (pathname === "/index.html") {
        body = rehearsalBanner(Buffer.from(body).toString("utf8"), runtime.status);
      }

      send(
        outgoing,
        wire(200, body, { "Content-Type": contentType(pathname) }),
        incoming.method === "HEAD"
      );
    } catch {
      send(outgoing, wire(404));
    }
  };
}

export async function runRehearsal({
  env = process.env,
  stdout = console.log,
  stderr = console.error,
  createServer = https.createServer
} = {}) {
  let options;
  try {
    options = parseRehearsalOptions(env);
  } catch {
    stderr("invalid rehearsal configuration");
    return 2;
  }

  let key;
  let cert;
  try {
    [key, cert] = await Promise.all([
      readFile(options.keyPath),
      readFile(options.certPath)
    ]);
  } catch {
    stderr("rehearsal TLS material unavailable");
    return 3;
  }

  const runtime = createRehearsalRuntime({
    port: options.port,
    status: options.status
  });

  const server = createServer(
    { key, cert },
    createRehearsalHandler({ runtime })
  );

  try {
    await new Promise((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(options.port, "127.0.0.1", resolveListen);
    });
  } catch {
    stderr("rehearsal listener unavailable");
    return 4;
  }

  stdout("HODLXXI Social V1.15 LOCAL REHEARSAL");
  stdout(`origin=${runtime.config.publicOrigin}`);
  stdout(`authority=${runtime.status}`);
  stdout(`subject=${REHEARSAL_SUBJECT}`);
  stdout("production_network_calls=0");

  const shutdown = () => {
    server.close();
    const timer = setTimeout(() => server.closeAllConnections?.(), 5000);
    timer.unref();
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  return 0;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runRehearsal().then((code) => {
    process.exitCode = code;
  });
}
