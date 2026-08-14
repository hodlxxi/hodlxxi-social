import { formatSocialAuthorityResult } from "./hodlxxi-authority-live-composition.mjs";
import { normalizeFeed, normalizeParticipants } from "../data/normalize.mjs";

const EMPTY = Object.freeze([]);
const keyPattern = /^[0-9a-f]{64}$/;
const plainSettled = (value) => value && typeof value === "object" && ["fulfilled", "rejected"].includes(value.status);

const safeAuthority = (subject, settled) => {
  if (!plainSettled(settled) || settled.status !== "fulfilled") return Object.freeze({ status: "limited", assertion: Object.freeze({ subject, assertedStatus: "limited", source: "unavailable", valid: false }) });
  try {
    formatSocialAuthorityResult(settled.value);
    const value = settled.value;
    if (value.subject !== subject || !["limited", "full"].includes(value.assertedIdentityClass)) throw new TypeError("authority subject mismatch");
    return Object.freeze({
      status: value.assertedIdentityClass,
      assertion: Object.freeze({ subject, assertedStatus: value.assertedIdentityClass, source: "hodlxxi-authority-probe", valid: true, evidenceRef: /operator/i.test(value.evidenceSource) ? "suppressed" : value.evidenceSource })
    });
  } catch {
    return Object.freeze({ status: "limited", assertion: Object.freeze({ subject, assertedStatus: "limited", source: "unavailable", valid: false }) });
  }
};

export function createParticipantShellSnapshot(result) {
  if (!result || typeof result !== "object" || !keyPattern.test(result.subject)) throw new TypeError("canonical participant subject required");
  if (!Number.isSafeInteger(result.noteLimit) || result.noteLimit < 1 || result.noteLimit > 10) throw new TypeError("bounded participant note limit required");
  const subject = result.subject;
  const authority = safeAuthority(subject, result.authority);
  let displayName = `Public key ${subject.slice(0, 8)}…${subject.slice(-6)}`;
  let profileAvailable = false;
  if (plainSettled(result.profile) && result.profile.status === "fulfilled" && result.profile.value?.id === subject) {
    try {
      const normalizedName = normalizeParticipants([result.profile.value])[0].displayName;
      if (!/operator/i.test(normalizedName)) { displayName = normalizedName; profileAvailable = true; }
    } catch {}
  }
  const participant = normalizeParticipants([{ id: subject, publicKey: subject, displayName }])[0];
  const admitted = [];
  if (plainSettled(result.notes) && result.notes.status === "fulfilled" && Array.isArray(result.notes.value)) {
    for (const note of result.notes.value.slice(0, result.noteLimit)) {
      if (note?.authorId !== subject) continue;
      try {
        const normalizedNote = normalizeFeed([note])[0];
        if (normalizedNote.audience === "PUBLIC" && !/operator/i.test(JSON.stringify(normalizedNote))) admitted.push(normalizedNote);
      } catch {}
    }
  }
  const notes = Object.freeze(admitted);
  return Object.freeze({
    currentViewerId: subject,
    profileAvailable,
    participants: Object.freeze([participant]),
    statuses: Object.freeze({ [subject]: authority.status }),
    externalAssertions: Object.freeze({ [subject]: authority.assertion }),
    edges: EMPTY, friendEdges: EMPTY, sponsorTrustEdges: EMPTY, notes,
    groups: EMPTY, conversations: EMPTY, messages: EMPTY, notifications: EMPTY
  });
}
