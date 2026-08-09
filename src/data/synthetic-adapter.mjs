import { assertions, conversations, edges, groups, notes, notifications, participants } from "../fixtures.mjs";
import { declareCapabilities } from "./adapter.mjs";
import { SocialCapability } from "./capabilities.mjs";

export class SyntheticSocialAdapter {
  constructor(viewerId = participants[1]?.id) {
    this.capabilities = declareCapabilities([
      SocialCapability.READ_CURRENT_VIEWER,
      SocialCapability.READ_PARTICIPANTS, SocialCapability.READ_RELATIONSHIPS, SocialCapability.READ_FEED,
      SocialCapability.READ_GROUPS, SocialCapability.READ_MESSAGES, SocialCapability.READ_NOTIFICATIONS,
      SocialCapability.READ_EXTERNAL_STATUS, SocialCapability.LOCAL_EPHEMERAL_WRITES
    ]);
    this.viewerId = viewerId;
    Object.freeze(this);
  }
  getCurrentViewer() { return this.viewerId; }
  listParticipants() { return participants; }
  listRelationships() { return edges; }
  listFeed() { return notes; }
  listGroups() { return groups; }
  listConversations() { return conversations; }
  listNotifications() { return notifications; }
  getExternalAccessAssertion(subject) { return assertions[subject]; }
}
