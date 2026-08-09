import { AccessStatus, EdgeType, normalizePublicKey } from "../domain.mjs";
import { readFromAdapter } from "./adapter.mjs";
import { SocialCapability } from "./capabilities.mjs";
import { normalizeConversations, normalizeExternalAssertion, normalizeFeed, normalizeGroups, normalizeNotifications, normalizeParticipants, normalizeRelationships } from "./normalize.mjs";

const safeViewer = (value, participants) => {
  try {
    const id = normalizePublicKey(value);
    return participants.some((person) => person.id === id) ? id : undefined;
  } catch { return undefined; }
};

const requireUniqueIds = (records, label) => {
  if (new Set(records.map(({ id }) => id)).size !== records.length) throw new TypeError(`${label} ids must be unique`);
};

const requireKnownIdentities = (identities, participantIds, label) => {
  if (identities.some((id) => !participantIds.has(id))) throw new TypeError(`${label} must reference canonical participants`);
};

export function createSocialDataService(adapter, { now = 100, authorityAdapter } = {}) {
  if (!Number.isFinite(now)) throw new TypeError("service time must be finite");
  return Object.freeze({
    load() {
      const currentViewer = readFromAdapter(adapter, SocialCapability.READ_CURRENT_VIEWER, "getCurrentViewer");
      const participants = normalizeParticipants(readFromAdapter(adapter, SocialCapability.READ_PARTICIPANTS, "listParticipants"));
      const relationships = normalizeRelationships(readFromAdapter(adapter, SocialCapability.READ_RELATIONSHIPS, "listRelationships"));
      const participantIds = new Set(participants.map(({ id }) => id));
      if (relationships.some(({ from, to }) => !participantIds.has(from) || !participantIds.has(to))) throw new TypeError("relationship endpoints must be canonical participants");
      const notes = normalizeFeed(readFromAdapter(adapter, SocialCapability.READ_FEED, "listFeed"));
      const groups = normalizeGroups(readFromAdapter(adapter, SocialCapability.READ_GROUPS, "listGroups"));
      const conversations = normalizeConversations(readFromAdapter(adapter, SocialCapability.READ_MESSAGES, "listConversations"));
      const notifications = normalizeNotifications(readFromAdapter(adapter, SocialCapability.READ_NOTIFICATIONS, "listNotifications"));
      for (const [records, label] of [[notes, "post"], [groups, "group"], [conversations, "conversation"], [notifications, "notification"]]) requireUniqueIds(records, label);
      const replyIds = notes.flatMap(({ replies }) => replies.map(({ id }) => id));
      if (new Set(replyIds).size !== replyIds.length) throw new TypeError("reply ids must be unique");
      requireKnownIdentities(notes.flatMap(({ authorId, replies }) => [authorId, ...replies.map((reply) => reply.authorId)]), participantIds, "feed authors");
      for (const group of groups) {
        requireKnownIdentities(group.memberIds, participantIds, "group members");
        if (new Set(group.memberIds).size !== group.memberIds.length) throw new TypeError("group members must be unique");
      }
      for (const conversation of conversations) {
        requireKnownIdentities([...conversation.memberIds, ...conversation.unreadFor, ...conversation.messages.map(({ authorId }) => authorId)], participantIds, "conversation identities");
        const members = new Set(conversation.memberIds);
        if (members.size !== conversation.memberIds.length || conversation.unreadFor.some((id) => !members.has(id)) || conversation.messages.some(({ authorId }) => !members.has(authorId))) throw new TypeError("conversation state must reference unique members");
      }
      requireKnownIdentities(notifications.map(({ actorId }) => actorId), participantIds, "notification actors");
      const groupIds = new Set(groups.map(({ id }) => id));
      const conversationIds = new Set(conversations.map(({ id }) => id));
      if (notifications.some(({ target }) => (target.type === "profile" && !participantIds.has(target.id)) || (target.type === "message" && !conversationIds.has(target.id)) || (target.type === "group" && !groupIds.has(target.id)))) throw new TypeError("notification targets must reference canonical records");
      const externalAssertions = Object.freeze(Object.fromEntries(participants.map(({ id }) => {
        let raw;
        try { raw = readFromAdapter(authorityAdapter, SocialCapability.READ_EXTERNAL_AUTHORITY, "readAssertion", id); } catch {}
        return [id, normalizeExternalAssertion(id, raw, now)];
      })));
      const statuses = Object.freeze(Object.fromEntries(participants.map(({ id }) => [id, externalAssertions[id].valid ? externalAssertions[id].assertedStatus : AccessStatus.LIMITED])));
      return Object.freeze({
        currentViewerId: safeViewer(currentViewer, participants), participants, statuses, externalAssertions,
        edges: relationships, friendEdges: Object.freeze(relationships.filter(({ type }) => type === EdgeType.FRIEND)),
        sponsorTrustEdges: Object.freeze(relationships.filter(({ type }) => type === EdgeType.SPONSOR_TRUST)),
        notes, groups, conversations, notifications
      });
    }
  });
}
