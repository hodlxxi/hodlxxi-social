import { declareCapabilities } from "../data/adapter.mjs";
import { SocialCapability } from "../data/capabilities.mjs";
import { createComposedSocialDataService } from "../data/composition.mjs";
import { HodlxxiAuthorityReadAdapter } from "../data/hodlxxi-authority-read-adapter.mjs";
import { AccessStatus } from "../domain.mjs";
import { AUTHORITY_EXIT_CODES, AUTHORITY_SCHEMA, AUTHORITY_SOURCE, AuthorityProbeError, formatAuthorityResult, parseAuthorityProbeArgs, runAuthorityProbe } from "./hodlxxi-authority-live-probe.mjs";

export const SOCIAL_AUTHORITY_PROJECTION_SCHEMA = "hodlxxi.social_authority_projection.v1";
const EMPTY = Object.freeze([]);
const PROJECTION_FIELDS = ["schema", "version", "subject", "assertedIdentityClass", "valid", "diagnostic", "evidenceSource", "observedAt"];
const READ_CAPABILITIES = [
  SocialCapability.READ_CURRENT_VIEWER, SocialCapability.READ_PARTICIPANTS,
  SocialCapability.READ_RELATIONSHIPS, SocialCapability.READ_FEED,
  SocialCapability.READ_GROUPS, SocialCapability.READ_MESSAGES,
  SocialCapability.READ_NOTIFICATIONS
];

export function createExplicitSubjectContext(subject) {
  const participant = Object.freeze({ id: subject, publicKey: subject, displayName: "Explicitly selected subject" });
  return Object.freeze({
    capabilities: declareCapabilities(READ_CAPABILITIES),
    getCurrentViewer: () => subject,
    listParticipants: () => Object.freeze([participant]),
    listRelationships: () => EMPTY,
    listFeed: () => EMPTY,
    listGroups: () => EMPTY,
    listConversations: () => EMPTY,
    listNotifications: () => EMPTY
  });
}

export function createExactSubjectTransport(subject, assertion) {
  return Object.freeze({ readAssertion: (candidate) => candidate === subject ? assertion : undefined });
}

const projection = ({ subject, assertedIdentityClass, valid, diagnostic, evidenceSource, observedAt }) => Object.freeze({
  schema: SOCIAL_AUTHORITY_PROJECTION_SCHEMA,
  version: 1,
  subject,
  assertedIdentityClass,
  valid,
  diagnostic,
  evidenceSource,
  observedAt
});

const extractExactProjection = (value) => {
  if (value === null || typeof value !== "object" || !Object.isFrozen(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("valid Social authority projection required");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== PROJECTION_FIELDS.length || keys.some((key) => typeof key !== "string") || PROJECTION_FIELDS.some((field) => !keys.includes(field))) throw new TypeError("valid Social authority projection required");
  const extracted = {};
  for (const field of PROJECTION_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new TypeError("valid Social authority projection required");
    extracted[field] = descriptor.value;
  }
  return extracted;
};

export async function runSocialAuthorityComposition(options, dependencies = {}) {
  const checked = parseAuthorityProbeArgs([
    "--origin", options?.origin,
    "--subject", options?.subject,
    "--timeout-ms", String(options?.timeoutMs)
  ]);
  const assertion = await runAuthorityProbe(checked, dependencies);
  const authorityAdapter = new HodlxxiAuthorityReadAdapter(createExactSubjectTransport(checked.subject, assertion));
  const service = createComposedSocialDataService({ socialAdapter: createExplicitSubjectContext(checked.subject), authorityAdapter });
  const snapshot = service.load();
  if (Object.hasOwn(dependencies, "observeComposition")) {
    if (typeof dependencies.observeComposition !== "function") throw new TypeError("composition observer must be a function");
    dependencies.observeComposition(Object.freeze({ snapshot }));
  }
  const normalized = snapshot.externalAssertions[checked.subject];
  const assertedIdentityClass = snapshot.statuses[checked.subject];
  const valid = normalized.valid === true && [AccessStatus.LIMITED, AccessStatus.FULL].includes(assertedIdentityClass);
  return projection({
    subject: checked.subject,
    assertedIdentityClass: valid ? assertedIdentityClass : AccessStatus.LIMITED,
    valid,
    diagnostic: valid ? "asserted" : "malformed",
    evidenceSource: valid ? normalized.evidenceRef : null,
    observedAt: valid ? assertion.observedAt : null
  });
}

export function formatSocialAuthorityResult(result) {
  const extracted = extractExactProjection(result);
  if (extracted.schema !== SOCIAL_AUTHORITY_PROJECTION_SCHEMA || extracted.version !== 1) throw new TypeError("valid Social authority projection required");
  formatAuthorityResult(Object.freeze({
    source: AUTHORITY_SOURCE,
    schema: AUTHORITY_SCHEMA,
    version: 1,
    subject: extracted.subject,
    status: extracted.assertedIdentityClass,
    valid: extracted.valid,
    diagnostic: extracted.diagnostic,
    evidenceSource: extracted.evidenceSource,
    observedAt: extracted.observedAt
  }));
  const canonical = projection(extracted);
  return Object.freeze({ output: JSON.stringify(canonical), exitCode: AUTHORITY_EXIT_CODES.asserted });
}

export function formatSocialAuthorityFailure(error) {
  const diagnostic = error instanceof AuthorityProbeError ? error.diagnostic : "malformed";
  const subject = error instanceof AuthorityProbeError ? error.assertion.subject : "0".repeat(64);
  const result = projection({ subject, assertedIdentityClass: AccessStatus.LIMITED, valid: false, diagnostic, evidenceSource: null, observedAt: null });
  return Object.freeze({ output: JSON.stringify(result), exitCode: AUTHORITY_EXIT_CODES[diagnostic] ?? AUTHORITY_EXIT_CODES.malformed });
}
