import test from "node:test";
import assert from "node:assert/strict";
import { AccessStatus, EdgeType, relationship } from "../src/domain.mjs";
import { RelationshipContext, relationshipContext, visibilityDecision } from "../src/visibility.mjs";

const [a,b,c,d] = ["a","b","c","d"].map((x) => x.repeat(64));
const edges = [relationship(EdgeType.FRIEND,a,b), relationship(EdgeType.FRIEND,b,c), relationship(EdgeType.SPONSOR_TRUST,a,d)];
test("only friend edges create social reachability", () => {
  assert.equal(relationshipContext(a,b,edges), RelationshipContext.DIRECT);
  assert.equal(relationshipContext(a,c,edges), RelationshipContext.FRIEND_OF_FRIEND);
  assert.equal(relationshipContext(a,d,edges), RelationshipContext.UNRELATED);
});
test("Limited and Full visibility differ deterministically", () => {
  assert.equal(visibilityDecision({viewerStatus:AccessStatus.LIMITED,context:RelationshipContext.DIRECT}).visible, true);
  assert.equal(visibilityDecision({viewerStatus:AccessStatus.LIMITED,context:RelationshipContext.FRIEND_OF_FRIEND}).visible, false);
  assert.equal(visibilityDecision({viewerStatus:AccessStatus.FULL,context:RelationshipContext.FRIEND_OF_FRIEND}).visible, true);
  assert.equal(visibilityDecision({viewerStatus:AccessStatus.FULL,context:RelationshipContext.UNRELATED}).visible, false);
});
test("unknown policy denies", () => assert.equal(visibilityDecision({viewerStatus:AccessStatus.FULL,context:RelationshipContext.DIRECT,policy:"unknown"}).visible, false));
test("unknown status denies in every context", () => {
  for (const context of Object.values(RelationshipContext)) assert.equal(visibilityDecision({viewerStatus:"unknown",context}).visible, false);
});
