import { AccessStatus, EdgeType, deriveAccess, participant, relationship } from "./domain.mjs";

export const keys = Object.freeze({ ada: "a".repeat(64), ben: "b".repeat(64), cy: "c".repeat(64), dia: "d".repeat(64) });
export const participants = Object.freeze([
  participant({ publicKey: keys.ada, displayName: "Ada · synthetic" }),
  participant({ publicKey: keys.ben, displayName: "Ben · synthetic" }),
  participant({ publicKey: keys.cy, displayName: "Cy · synthetic" }),
  participant({ publicKey: keys.dia, displayName: "Dia · synthetic" })
]);
export const assertions = Object.freeze({
  [keys.ada]: Object.freeze({ source: "hodlxxi-crt", version: 1, subject: keys.ada, status: AccessStatus.OPERATOR, expiresAt: 200 }),
  [keys.ben]: Object.freeze({ source: "hodlxxi-crt", version: 1, subject: keys.ben, status: AccessStatus.FULL, expiresAt: 200 }),
  [keys.dia]: Object.freeze({ source: "hodlxxi-crt", version: 1, subject: keys.dia, status: AccessStatus.FULL, expiresAt: 200 })
});
export const statuses = Object.freeze(Object.fromEntries(participants.map(({ id }) => [id, deriveAccess(id, assertions[id], 100)])));
export const edges = Object.freeze([
  relationship(EdgeType.FRIEND, keys.ada, keys.ben), relationship(EdgeType.FRIEND, keys.ben, keys.cy),
  relationship(EdgeType.SPONSOR_TRUST, keys.ada, keys.dia)
]);
export const notes = Object.freeze([
  Object.freeze({ id: "synthetic-note-1", authorId: keys.ben, audience: "PUBLIC", body: "Building a social layer where trust and friendship stay distinct.", timestamp: "Today · 09:42", reactions: 21, comments: 2, reposts: 4, media: "Local network map · synthetic preview", replies: Object.freeze([
    Object.freeze({ id: "synthetic-reply-1", authorId: keys.ada, body: "Clear boundaries make social context more useful." }),
    Object.freeze({ id: "synthetic-reply-2", authorId: keys.cy, body: "And visibility still follows the viewer policy." })
  ]) }),
  Object.freeze({ id: "synthetic-note-2", authorId: keys.cy, audience: "FRIENDS", body: "Limited access still supports direct human connection.", timestamp: "Yesterday · 16:18", reactions: 8, comments: 0, reposts: 1, replies: Object.freeze([]) }),
  Object.freeze({ id: "synthetic-note-3", authorId: keys.ada, audience: "FULL_NETWORK", body: "A small offline demo can still be honest about what is local and what is externally derived.", timestamp: "Friday · 11:05", reactions: 34, comments: 1, reposts: 6, media: "Local activity chart · demo data", replies: Object.freeze([
    Object.freeze({ id: "synthetic-reply-3", authorId: keys.ben, body: "No live-network claim needed." })
  ]) })
]);

const freezeMessages = (items) => Object.freeze(items.map((item) => Object.freeze({ ...item })));
export const conversations = Object.freeze([
  Object.freeze({ id: "chat-01", memberIds: Object.freeze([keys.ada, keys.ben]), unreadFor: Object.freeze([keys.ada]), messages: freezeMessages([
    { authorId: keys.ben, body: "The local product shell is taking shape.", timestamp: "Today · 09:42" },
    { authorId: keys.ada, body: "Good. Messaging and covenant trust stay separate.", timestamp: "Today · 09:45" }
  ]) }),
  Object.freeze({ id: "chat-02", memberIds: Object.freeze([keys.ada, keys.cy]), unreadFor: Object.freeze([]), messages: freezeMessages([
    { authorId: keys.cy, body: "Visibility still follows the current viewer policy.", timestamp: "Yesterday · 16:18" }
  ]) })
]);

export const groups = Object.freeze([
  Object.freeze({ id: "group-01", title: "Local Builders", description: "A synthetic space for product-shell notes.", memberIds: Object.freeze([keys.ada, keys.ben, keys.cy]), activity: "Today · Interface boundaries reviewed locally" }),
  Object.freeze({ id: "group-02", title: "Design Study", description: "A local fixture for small-screen layout discussion.", memberIds: Object.freeze([keys.ben, keys.dia]), activity: "Yesterday · Mobile spacing explored locally" })
]);

const freezeNotifications = (items) => Object.freeze(items.map((item) => Object.freeze({ ...item, target: Object.freeze({ ...item.target }) })));
export const notifications = freezeNotifications([
  { id: "local-notice-friend", actorId: keys.ada, kind: "friend", action: "shared profile and social connection activity", targetLabel: "Profile", timestamp: "Today · 10:08", unread: true, target: { type: "profile", id: keys.ada } },
  { id: "local-notice-reaction", actorId: keys.ben, kind: "reaction", action: "reacted to a synthetic local post", targetLabel: "Home", timestamp: "Today · 09:54", unread: true, target: { type: "home" } },
  { id: "local-notice-reply", actorId: keys.cy, kind: "reply", action: "replied to a demo post", targetLabel: "Home", timestamp: "Yesterday · 16:22", unread: false, target: { type: "home" } },
  { id: "local-notice-message", actorId: keys.ada, kind: "message", action: "added a new local demo message", targetLabel: "Messages", timestamp: "Yesterday · 14:06", unread: true, target: { type: "message", id: "chat-01" } },
  { id: "local-notice-group", actorId: keys.ben, kind: "group", action: "added synthetic local group activity", targetLabel: "Local Builders", timestamp: "Friday · 11:18", unread: false, target: { type: "group", id: "group-01" } }
]);
