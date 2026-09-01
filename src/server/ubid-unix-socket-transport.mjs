import http from "node:http";
import { Readable } from "node:stream";
import { canonicalUnixSocketPath } from "./social-oauth-config.mjs";

export const UBID_SERVICE_TOKEN_PATH =
  "/internal/v1/social/service-token";
export const UBID_FULL_DIRECTORY_PATH =
  "/internal/v1/social/full-directory";

const MAX_REQUEST_BODY_BYTES = 64 * 1024;
const MAX_RESPONSE_HEADER_BYTES = 16 * 1024;
const MAX_RESPONSE_HEADERS = 32;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HEADER_VALUE = /^[\t\x20-\x7e]*$/;

const unavailable = () => new Error("full_directory_unavailable");
const failure = () => { throw unavailable(); };

const endpoint = (value, expectedPath) => {
  try {
    if (typeof value !== "string") failure();
    const url = new URL(value);
    if (
      url.href !== value ||
      url.protocol !== "https:" ||
      !url.hostname ||
      url.hostname.endsWith(".") ||
      url.username ||
      url.password ||
      url.pathname !== expectedPath ||
      url.search ||
      url.hash
    ) failure();
    return Object.freeze({ href: url.href, host: url.host, path: url.pathname });
  } catch {
    failure();
  }
};

const inputHeaders = (value, expected) => {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) failure();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.length !== expected.length ||
      keys.some((key) => typeof key !== "string")
    ) failure();
    const normalized = new Map();
    for (const key of keys) {
      const descriptor = descriptors[key];
      const name = key.toLowerCase();
      if (
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !expected.includes(name) ||
        normalized.has(name) ||
        typeof descriptor.value !== "string" ||
        descriptor.value.length > 8192 ||
        !HEADER_VALUE.test(descriptor.value)
      ) failure();
      normalized.set(name, descriptor.value);
    }
    if (expected.some((name) => !normalized.has(name))) failure();
    return normalized;
  } catch {
    failure();
  }
};

const exactRecord = (value, fields) => {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) failure();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.length !== fields.length ||
      keys.some((key) => typeof key !== "string" || !fields.includes(key)) ||
      fields.some((field) => !Object.hasOwn(descriptors, field)) ||
      keys.some((key) =>
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value")
      )
    ) failure();
    return Object.fromEntries(
      fields.map((field) => [field, descriptors[field].value])
    );
  } catch {
    failure();
  }
};

const responseHeaders = (rawHeaders) => {
  if (
    !Array.isArray(rawHeaders) ||
    rawHeaders.length % 2 !== 0 ||
    rawHeaders.length > MAX_RESPONSE_HEADERS * 2
  ) failure();
  const values = new Map();
  let bytes = 0;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (
      typeof name !== "string" ||
      typeof value !== "string" ||
      !HEADER_NAME.test(name) ||
      !HEADER_VALUE.test(value)
    ) failure();
    const normalized = name.toLowerCase();
    if (values.has(normalized)) failure();
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    if (bytes > MAX_RESPONSE_HEADER_BYTES) failure();
    values.set(normalized, value);
  }
  return Object.freeze({
    get(name) {
      if (typeof name !== "string") return null;
      return values.get(name.toLowerCase()) ?? null;
    }
  });
};

const tokenRequest = (init) => {
  if (
    init.method !== "POST" ||
    typeof init.body !== "string" ||
    Buffer.byteLength(init.body, "utf8") === 0 ||
    Buffer.byteLength(init.body, "utf8") > MAX_REQUEST_BODY_BYTES
  ) failure();
  const headers = inputHeaders(init.headers, ["accept", "content-type"]);
  if (
    headers.get("accept") !== "application/json" ||
    headers.get("content-type") !== "application/x-www-form-urlencoded"
  ) failure();
  return { body: init.body, headers };
};

const directoryRequest = (init) => {
  if (init.method !== "GET" || Object.hasOwn(init, "body")) failure();
  const headers = inputHeaders(init.headers, [
    "accept",
    "authorization",
    "x-hodlxxi-viewer-authorization"
  ]);
  if (
    headers.get("accept") !== "application/json" ||
    !/^Bearer [^\u0000-\u0020\u007f]{1,8192}$/.test(
      headers.get("authorization")
    ) ||
    !/^Bearer [^\u0000-\u0020\u007f]{1,8192}$/.test(
      headers.get("x-hodlxxi-viewer-authorization")
    )
  ) failure();
  return { body: undefined, headers };
};

const outgoingHeaders = (headers, logicalHost) => {
  const result = {};
  for (const [name, value] of headers) result[name] = value;
  result.Host = logicalHost;
  return result;
};

export function createUbidUnixSocketTransport(configuration, dependencies) {
  let socketPath;
  let serviceTokenUrl;
  let directoryUrl;
  let requestImpl;
  try {
    ({ socketPath, serviceTokenUrl, directoryUrl } = exactRecord(
      configuration,
      ["socketPath", "serviceTokenUrl", "directoryUrl"]
    ));
    if (dependencies === undefined) {
      requestImpl = http.request;
    } else {
      ({ requestImpl } = exactRecord(dependencies, ["requestImpl"]));
    }
    if (typeof requestImpl !== "function") failure();
    socketPath = canonicalUnixSocketPath(socketPath);
  } catch {
    failure();
  }
  const serviceTokenEndpoint = endpoint(
    serviceTokenUrl,
    UBID_SERVICE_TOKEN_PATH
  );
  const directoryEndpoint = endpoint(
    directoryUrl,
    UBID_FULL_DIRECTORY_PATH
  );

  return async function unixSocketFetch(url, init) {
    try {
      let selected;
      if (url === serviceTokenEndpoint.href) {
        selected = serviceTokenEndpoint;
        init = exactRecord(init, [
          "method", "headers", "body", "credentials", "redirect", "signal"
        ]);
      } else if (url === directoryEndpoint.href) {
        selected = directoryEndpoint;
        init = exactRecord(init, [
          "method", "headers", "credentials", "redirect", "signal"
        ]);
      } else {
        failure();
      }
      if (
        init.credentials !== "omit" ||
        init.redirect !== "error" ||
        !init.signal ||
        typeof init.signal.aborted !== "boolean" ||
        typeof init.signal.addEventListener !== "function" ||
        typeof init.signal.removeEventListener !== "function"
      ) failure();

      let request;
      if (selected === serviceTokenEndpoint) {
        request = tokenRequest(init);
      } else {
        request = directoryRequest(init);
      }

      if (init.signal.aborted) failure();
      return await new Promise((resolve, reject) => {
        let outgoing;
        let incoming;
        let settled = false;
        let cleaned = false;

        const cleanup = () => {
          if (cleaned) return;
          cleaned = true;
          init.signal.removeEventListener("abort", abort);
        };
        const close = () => {
          try { outgoing?.destroy?.(); } catch {}
          try { incoming?.destroy?.(); } catch {}
        };
        const rejectUnavailable = () => {
          close();
          if (settled) return;
          settled = true;
          cleanup();
          reject(unavailable());
        };
        const abort = () => rejectUnavailable();

        init.signal.addEventListener("abort", abort, { once: true });
        try {
          outgoing = requestImpl({
            socketPath,
            method: init.method,
            path: selected.path,
            headers: outgoingHeaders(request.headers, selected.host),
            maxHeaderSize: MAX_RESPONSE_HEADER_BYTES,
            setHost: false
          }, (response) => {
            incoming = response;
            try {
              if (
                !response ||
                !Number.isSafeInteger(response.statusCode) ||
                response.statusCode < 100 ||
                response.statusCode > 599 ||
                (response.statusCode >= 300 && response.statusCode <= 399) ||
                typeof response.once !== "function" ||
                typeof response.destroy !== "function"
              ) failure();
              const headers = responseHeaders(response.rawHeaders);
              const body = Readable.toWeb(response);
              response.once("end", cleanup);
              response.once("close", cleanup);
              if (settled) {
                close();
                return;
              }
              settled = true;
              resolve(Object.freeze({
                status: response.statusCode,
                headers,
                body
              }));
            } catch {
              rejectUnavailable();
            }
          });
          if (
            !outgoing ||
            typeof outgoing.once !== "function" ||
            typeof outgoing.end !== "function" ||
            typeof outgoing.destroy !== "function"
          ) failure();
          outgoing.once("error", rejectUnavailable);
          outgoing.once("timeout", rejectUnavailable);
          outgoing.maxHeadersCount = MAX_RESPONSE_HEADERS;
          outgoing.end(request.body);
        } catch {
          rejectUnavailable();
        }
      });
    } catch {
      failure();
    }
  };
}
