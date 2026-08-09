import { AccessStatus, EdgeType, normalizePublicKey } from "./domain.mjs";

export const RelationshipContext = Object.freeze({ SELF: "self", DIRECT: "direct", FRIEND_OF_FRIEND: "friend-of-friend", UNRELATED: "unrelated" });

export function relationshipContext(viewer, subject, edges) {
  const a = normalizePublicKey(viewer); const b = normalizePublicKey(subject);
  if (a === b) return RelationshipContext.SELF;
  const friends = edges.filter((edge) => edge.type === EdgeType.FRIEND);
  const adjacent = (x, y) => friends.some((edge) => (edge.from === x && edge.to === y) || (edge.from === y && edge.to === x));
  if (adjacent(a, b)) return RelationshipContext.DIRECT;
  const nodes = new Set(friends.flatMap((edge) => [edge.from, edge.to]));
  if ([...nodes].some((middle) => adjacent(a, middle) && adjacent(middle, b))) return RelationshipContext.FRIEND_OF_FRIEND;
  return RelationshipContext.UNRELATED;
}

export function visibilityDecision({ viewerStatus, context, policy = "social" }) {
  if (!Object.values(AccessStatus).includes(viewerStatus)) return Object.freeze({ visible: false, reason: "deny-by-default" });
  if (policy !== "social" || !Object.values(RelationshipContext).includes(context)) return Object.freeze({ visible: false, reason: "deny-by-default" });
  if (context === RelationshipContext.SELF) return Object.freeze({ visible: true, reason: "self" });
  if (viewerStatus === AccessStatus.LIMITED) return Object.freeze({ visible: context === RelationshipContext.DIRECT, reason: "limited-direct-only" });
  if (viewerStatus === AccessStatus.FULL || viewerStatus === AccessStatus.OPERATOR) return Object.freeze({ visible: context !== RelationshipContext.UNRELATED, reason: "full-social-graph" });
  return Object.freeze({ visible: false, reason: "deny-by-default" });
}
