export const SocialCapability = Object.freeze({
  READ_CURRENT_VIEWER: "read-current-viewer",
  READ_PARTICIPANTS: "read-participants",
  READ_RELATIONSHIPS: "read-relationships",
  READ_FEED: "read-feed",
  READ_GROUPS: "read-groups",
  READ_MESSAGES: "read-messages",
  READ_NOTIFICATIONS: "read-notifications",
  READ_EXTERNAL_STATUS: "read-external-status",
  LOCAL_EPHEMERAL_WRITES: "local-ephemeral-writes"
});

export const ALL_SOCIAL_CAPABILITIES = Object.freeze(Object.values(SocialCapability));
