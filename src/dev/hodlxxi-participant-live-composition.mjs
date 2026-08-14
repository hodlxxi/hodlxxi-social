import { createComposedSocialDataService } from "../data/composition.mjs";
import { NostrPublicReadAdapter } from "../data/nostr-public-read-adapter.mjs";
import { WebSocketNostrReadTransport } from "../data/nostr-websocket-read-transport.mjs";
import { formatSocialAuthorityResult, runSocialAuthorityComposition } from "./hodlxxi-authority-live-composition.mjs";
import { parseAuthorityProbeArgs } from "./hodlxxi-authority-live-probe.mjs";

export const PARTICIPANT_LIVE_LIMITS = Object.freeze({ minNotes: 1, maxNotes: 10 });

const defaultTransportFactory = (options) => new WebSocketNostrReadTransport(options);
const defaultAdapterFactory = (options) => NostrPublicReadAdapter.create(options);

export function parseParticipantLiveOptions({ origin, relayUrl, subject, timeoutMs, noteLimit } = {}, { transportFactory = defaultTransportFactory } = {}) {
  const authority = parseAuthorityProbeArgs(["--origin", origin, "--subject", subject, "--timeout-ms", String(timeoutMs)]);
  const limit = Number(noteLimit);
  if (!Number.isSafeInteger(limit) || limit < PARTICIPANT_LIVE_LIMITS.minNotes || limit > PARTICIPANT_LIVE_LIMITS.maxNotes) {
    throw new TypeError(`note limit must be between ${PARTICIPANT_LIVE_LIMITS.minNotes} and ${PARTICIPANT_LIVE_LIMITS.maxNotes}`);
  }
  const transport = transportFactory({ relayUrl, openTimeoutMs: authority.timeoutMs, readTimeoutMs: authority.timeoutMs, maxEvents: 1 });
  if (relayUrl !== transport.relayUrl) throw new TypeError("relay URL must be canonical");
  return Object.freeze({ ...authority, relayUrl: transport.relayUrl, noteLimit: limit });
}

const readNostr = async ({ relayUrl, subject, timeoutMs, kind, maxEvents }, { transportFactory, adapterFactory, compose }) => {
  const transport = transportFactory({ relayUrl, openTimeoutMs: timeoutMs, readTimeoutMs: timeoutMs, maxEvents });
  const filteredTransport = Object.freeze({
    read: () => transport.read(Object.freeze({ authors: Object.freeze([subject]), kinds: Object.freeze([kind]), limit: maxEvents }))
  });
  const adapter = await adapterFactory({ transport: filteredTransport, viewerId: subject });
  return compose({ socialAdapter: adapter }).load();
};

export async function loadParticipantLive(options, {
  authorityCompose = runSocialAuthorityComposition,
  authorityFormat = formatSocialAuthorityResult,
  transportFactory = defaultTransportFactory,
  adapterFactory = defaultAdapterFactory,
  compose = createComposedSocialDataService
} = {}) {
  const checked = parseParticipantLiveOptions(options, { transportFactory });
  const authority = Promise.resolve().then(() => authorityCompose({ origin: checked.origin, subject: checked.subject, timeoutMs: checked.timeoutMs }))
    .then((value) => { authorityFormat(value); return value; });
  const dependencies = { transportFactory, adapterFactory, compose };
  const profile = readNostr({ ...checked, kind: 0, maxEvents: 1 }, dependencies)
    .then((data) => {
      if (data.participants.some(({ id }) => id !== checked.subject)) throw new TypeError("profile read returned an off-subject participant");
      return data.participants.find(({ id }) => id === checked.subject) ?? null;
    });
  const notes = readNostr({ ...checked, kind: 1, maxEvents: checked.noteLimit }, dependencies)
    .then((data) => {
      if (data.participants.some(({ id }) => id !== checked.subject) || data.notes.some(({ authorId }) => authorId !== checked.subject)) throw new TypeError("note read returned off-subject data");
      return Object.freeze([...data.notes]);
    });
  const [authorityResult, profileResult, notesResult] = await Promise.allSettled([authority, profile, notes]);
  return Object.freeze({
    subject: checked.subject,
    relayUrl: checked.relayUrl,
    noteLimit: checked.noteLimit,
    authority: authorityResult,
    profile: profileResult,
    notes: notesResult
  });
}
