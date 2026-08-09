import { normalizePublicKey } from "../domain.mjs";
import { NostrPublicReadAdapter } from "../data/nostr-public-read-adapter.mjs";
import { WebSocketNostrReadTransport } from "../data/nostr-websocket-read-transport.mjs";

export const PROBE_LIMITS = Object.freeze({
  defaultLimit: 3,
  maxLimit: 10,
  defaultTimeoutMs: 5_000,
  minTimeoutMs: 250,
  maxTimeoutMs: 30_000,
  previewCharacters: 120
});

export const EXIT_CODES = Object.freeze({ argument: 2, transport: 3, timeout: 4, malformed: 5, validation: 6 });
const SUPPORTED_KINDS = new Set([0, 1]);
const ADAPTER_FILTER = Object.freeze({ kinds: Object.freeze([0, 1]) });
const DIAGNOSTIC_VIEWER = "0".repeat(64);

export class ProbeError extends Error {
  constructor(category, message, options = {}) {
    super(message, options);
    this.name = "ProbeError";
    this.category = category;
  }
}

function argumentError(message, cause) {
  return new ProbeError("argument", message, cause === undefined ? {} : { cause });
}

function parseInteger(value, option) {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) throw argumentError(`${option} requires an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw argumentError(`${option} requires a safe integer`);
  return parsed;
}

export function parseProbeArgs(argv) {
  if (!Array.isArray(argv) || !argv.every((value) => typeof value === "string")) throw argumentError("arguments must be strings");
  const values = new Map();
  let json = false;
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--json") {
      if (json) throw argumentError("duplicate option: --json");
      json = true;
      continue;
    }
    if (!["--relay", "--kind", "--author", "--limit", "--timeout-ms"].includes(option)) {
      throw argumentError(`unsupported option: ${option}`);
    }
    if (values.has(option)) throw argumentError(`duplicate option: ${option}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw argumentError(`${option} requires a value`);
    values.set(option, value);
    index += 1;
  }

  const relayUrl = values.get("--relay");
  if (!relayUrl) throw argumentError("--relay is required");
  const kindValue = values.get("--kind");
  if (kindValue === undefined) throw argumentError("--kind is required");
  const kind = parseInteger(kindValue, "--kind");
  if (!SUPPORTED_KINDS.has(kind)) throw argumentError("--kind must be 0 or 1");

  let author;
  if (values.has("--author")) {
    const supplied = values.get("--author");
    if (!/^[0-9a-fA-F]{64}$/.test(supplied)) throw argumentError("--author must be a 64-character hexadecimal public key");
    try { author = normalizePublicKey(supplied); } catch (error) { throw argumentError("--author is invalid", error); }
  }

  const limit = values.has("--limit") ? parseInteger(values.get("--limit"), "--limit") : PROBE_LIMITS.defaultLimit;
  if (limit < 1 || limit > PROBE_LIMITS.maxLimit) throw argumentError(`--limit must be between 1 and ${PROBE_LIMITS.maxLimit}`);
  const timeoutMs = values.has("--timeout-ms") ? parseInteger(values.get("--timeout-ms"), "--timeout-ms") : PROBE_LIMITS.defaultTimeoutMs;
  if (timeoutMs < PROBE_LIMITS.minTimeoutMs || timeoutMs > PROBE_LIMITS.maxTimeoutMs) {
    throw argumentError(`--timeout-ms must be between ${PROBE_LIMITS.minTimeoutMs} and ${PROBE_LIMITS.maxTimeoutMs}`);
  }
  return Object.freeze({ relayUrl, kind, author, limit, timeoutMs, json });
}

const defaultTransportFactory = (options) => new WebSocketNostrReadTransport(options);
const defaultAdapterFactory = (options) => NostrPublicReadAdapter.create(options);
const preview = (value) => String(value).replace(/\s+/g, " ").trim().slice(0, PROBE_LIMITS.previewCharacters);
const eventMatchesFilter = (event, filter) => event?.kind === filter.kinds[0] &&
  (!filter.authors || (typeof event.pubkey === "string" && event.pubkey.toLowerCase() === filter.authors[0]));

function diagnosticRecords(adapter, kind, limit) {
  if (kind === 0) {
    const participants = adapter.listParticipants();
    if (!Array.isArray(participants)) throw new ProbeError("malformed", "normalized participant result is malformed");
    return participants.slice(0, limit).map(({ publicKey, displayName }) => Object.freeze({
      type: "profile", author: publicKey, preview: preview(displayName)
    }));
  }
  const feed = adapter.listFeed();
  if (!Array.isArray(feed)) throw new ProbeError("malformed", "normalized feed result is malformed");
  return feed.slice(0, limit).map(({ id, authorId, timestamp, body }) => Object.freeze({
    type: "note", id, author: authorId, kind: 1,
    created_at: Math.floor(new Date(timestamp).getTime() / 1000), preview: preview(body)
  }));
}

function classifyFailure(error) {
  if (error instanceof ProbeError) return error;
  const message = error instanceof Error ? error.message : "probe failed";
  if (/timed out|timeout/i.test(message)) return new ProbeError("timeout", message, { cause: error });
  if (/malformed|message must be text|unsupported Nostr relay frame|wrong subscription/i.test(message)) {
    return new ProbeError("malformed", message, { cause: error });
  }
  if (error instanceof TypeError) return new ProbeError("validation", message, { cause: error });
  return new ProbeError("transport", message, { cause: error });
}

export async function runProbe(options, {
  transportFactory = defaultTransportFactory,
  adapterFactory = defaultAdapterFactory,
  now = () => Date.now()
} = {}) {
  const filter = Object.freeze({
    kinds: Object.freeze([options.kind]),
    ...(options.author ? { authors: Object.freeze([options.author]) } : {}),
    limit: options.limit
  });
  let transport;
  try {
    transport = transportFactory({
      relayUrl: options.relayUrl,
      openTimeoutMs: options.timeoutMs,
      readTimeoutMs: options.timeoutMs,
      maxEvents: options.limit
    });
  } catch (error) {
    throw argumentError(error instanceof Error ? error.message : "invalid relay configuration", error);
  }
  if (!transport || typeof transport.read !== "function") throw new ProbeError("transport", "transport factory returned an invalid transport");

  let reads = 0;
  let rawCount = 0;
  const constrainedTransport = Object.freeze({
    async read(adapterFilter) {
      reads += 1;
      if (reads !== 1 || JSON.stringify(adapterFilter) !== JSON.stringify(ADAPTER_FILTER)) {
        throw new ProbeError("validation", "public adapter requested an unexpected read");
      }
      let events;
      try { events = await transport.read(filter); } catch (error) { throw classifyFailure(error); }
      if (!Array.isArray(events)) throw new ProbeError("malformed", "relay transport must return an event array");
      if (!events.every((event) => eventMatchesFilter(event, filter))) {
        throw new ProbeError("validation", "relay event did not match the requested filter");
      }
      rawCount = events.length;
      return events;
    }
  });

  const startedAt = now();
  try {
    let adapter;
    try {
      adapter = await adapterFactory({ transport: constrainedTransport, viewerId: options.author ?? DIAGNOSTIC_VIEWER });
    } catch (error) {
      if (error instanceof ProbeError) throw error;
      throw new ProbeError("validation", "public event normalization failed", { cause: error });
    }
    if (reads !== 1) throw new ProbeError("validation", "public adapter did not perform exactly one read");
    const records = Object.freeze(diagnosticRecords(adapter, options.kind, options.limit));
    const elapsedMs = Math.max(0, Math.min(options.timeoutMs, Math.trunc(now() - startedAt)));
    return Object.freeze({
      relay: transport.relayUrl ?? options.relayUrl,
      filter,
      rawEventsReceived: rawCount,
      acceptedEvents: records.length,
      rejectedEvents: null,
      completionReason: rawCount === 0 ? "zero-events" : "completed",
      elapsedMs,
      records
    });
  } catch (error) {
    throw classifyFailure(error);
  }
}

export function formatProbeResult(result, { json = false } = {}) {
  if (json) return JSON.stringify(result);
  const lines = [
    `relay: ${result.relay}`,
    `filter: ${JSON.stringify(result.filter)}`,
    `raw events received: ${result.rawEventsReceived}`,
    `accepted events: ${result.acceptedEvents}`,
    "rejected events: unavailable",
    `completion reason: ${result.completionReason}`,
    `elapsed ms: ${result.elapsedMs}`
  ];
  for (const record of result.records) lines.push(`record: ${JSON.stringify(record)}`);
  return lines.join("\n");
}

export function formatProbeFailure(error, { json = false } = {}) {
  const failure = classifyFailure(error);
  const messages = Object.freeze({
    argument: "invalid command arguments or relay URL",
    transport: "relay transport failed",
    timeout: "relay read timed out",
    malformed: "malformed relay response",
    validation: "relay event validation failed"
  });
  const category = Object.hasOwn(messages, failure.category) ? failure.category : "transport";
  const diagnostic = Object.freeze({ error: category, message: messages[category] });
  return Object.freeze({ exitCode: EXIT_CODES[category], output: json ? JSON.stringify(diagnostic) : `${category}: ${messages[category]}` });
}
