import { normalizePublicKey, participant } from "../domain.mjs";
import { mapNoteEvent, mapProfileEvent } from "../nostr.mjs";
import { declareCapabilities } from "./adapter.mjs";
import { SocialCapability } from "./capabilities.mjs";

const EMPTY = Object.freeze([]);
const INITIALIZER = Symbol("NostrPublicReadAdapter initializer");
const PUBLIC_FILTER = Object.freeze({ kinds: Object.freeze([0, 1]) });

const capabilities = Object.freeze([
  SocialCapability.READ_CURRENT_VIEWER,
  SocialCapability.READ_PARTICIPANTS,
  SocialCapability.READ_RELATIONSHIPS,
  SocialCapability.READ_FEED,
  SocialCapability.READ_GROUPS,
  SocialCapability.READ_MESSAGES,
  SocialCapability.READ_NOTIFICATIONS,
  SocialCapability.READ_PUBLIC_NOSTR
]);

const eventTieBreak = (event) => JSON.stringify([event.content, event.sig, event.tags]);
const eventOrder = (left, right) =>
  left.kind - right.kind ||
  left.pubkey.localeCompare(right.pubkey) ||
  left.created_at - right.created_at ||
  left.id.localeCompare(right.id) ||
  eventTieBreak(left).localeCompare(eventTieBreak(right));

export class NostrPublicReadAdapter {
  static async create({ transport, viewerId } = {}) {
    if (!transport || typeof transport.read !== "function") throw new TypeError("public Nostr read transport is required");
    const normalizedViewer = normalizePublicKey(viewerId);
    const events = await transport.read(PUBLIC_FILTER);
    if (!Array.isArray(events)) throw new TypeError("public Nostr read transport must return an array");

    const profiles = new Map();
    const notes = new Map();
    for (const event of [...events].sort(eventOrder)) {
      if (event?.kind === 0) {
        const mapped = mapProfileEvent(event);
        profiles.set(mapped.id, mapped);
      } else if (event?.kind === 1) {
        const mapped = mapNoteEvent(event);
        notes.set(mapped.id, mapped);
      } else {
        throw new TypeError("unsupported public Nostr event kind");
      }
    }

    const participantIds = new Set([...profiles.keys(), ...[...notes.values()].map(({ authorId }) => authorId)]);
    const participants = Object.freeze([...participantIds].sort().map((id) => profiles.get(id) ?? participant({ publicKey: id, displayName: "Participant" })));
    const feed = Object.freeze([...notes.values()].sort((left, right) => left.createdAt - right.createdAt || left.id.localeCompare(right.id)).map((note) => Object.freeze({
      id: note.id,
      authorId: note.authorId,
      audience: "PUBLIC",
      body: note.body,
      timestamp: new Date(note.createdAt * 1000).toISOString(),
      reactions: 0,
      comments: 0,
      reposts: 0,
      replies: EMPTY
    })));
    return new NostrPublicReadAdapter(INITIALIZER, normalizedViewer, participants, feed);
  }

  constructor(initializer, viewerId, participants, feed) {
    if (initializer !== INITIALIZER) throw new TypeError("use NostrPublicReadAdapter.create");
    this.capabilities = declareCapabilities(capabilities);
    this.viewerId = viewerId;
    this.participants = participants;
    this.feed = feed;
    Object.freeze(this);
  }

  getCurrentViewer() { return this.viewerId; }
  listParticipants() { return this.participants; }
  listRelationships() { return EMPTY; }
  listFeed() { return this.feed; }
  listGroups() { return EMPTY; }
  listConversations() { return EMPTY; }
  listNotifications() { return EMPTY; }
}
