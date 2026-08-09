import { createComposedSocialDataService } from "../data/composition.mjs";
import { NostrPublicReadAdapter } from "../data/nostr-public-read-adapter.mjs";
import { WebSocketNostrReadTransport } from "../data/nostr-websocket-read-transport.mjs";

export const DEV_LIVE_LIMITS = Object.freeze({ defaultEvents: 3, maxEvents: 10, timeoutMs: 5_000 });
export const DEMO_VIEWER_PUBLIC_KEY = "0".repeat(64);

const defaultTransportFactory = (options) => new WebSocketNostrReadTransport(options);
const defaultAdapterFactory = (options) => NostrPublicReadAdapter.create(options);

function boundedLimit(value) {
  const limit = value === undefined ? DEV_LIVE_LIMITS.defaultEvents : Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > DEV_LIVE_LIMITS.maxEvents) {
    throw new TypeError(`event limit must be between 1 and ${DEV_LIVE_LIMITS.maxEvents}`);
  }
  return limit;
}

export async function loadDevLiveSocial({ relayUrl, limit } = {}, {
  transportFactory = defaultTransportFactory,
  adapterFactory = defaultAdapterFactory,
  compose = createComposedSocialDataService,
  webSocketFactory
} = {}) {
  const maxEvents = boundedLimit(limit);
  const transport = transportFactory({
    relayUrl,
    openTimeoutMs: DEV_LIVE_LIMITS.timeoutMs,
    readTimeoutMs: DEV_LIVE_LIMITS.timeoutMs,
    maxEvents,
    ...(webSocketFactory ? { webSocketFactory } : {})
  });
  const socialAdapter = await adapterFactory({ transport, viewerId: DEMO_VIEWER_PUBLIC_KEY });
  const data = compose({ socialAdapter }).load();
  return Object.freeze({ relayUrl: transport.relayUrl, limit: maxEvents, data });
}
