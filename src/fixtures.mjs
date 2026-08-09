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
  Object.freeze({ id: "synthetic-note-1", authorId: keys.ben, body: "Building a social layer where trust and friendship stay distinct.", createdAt: 1 }),
  Object.freeze({ id: "synthetic-note-2", authorId: keys.cy, body: "Limited access still supports direct human connection.", createdAt: 2 })
]);
