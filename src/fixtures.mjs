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
