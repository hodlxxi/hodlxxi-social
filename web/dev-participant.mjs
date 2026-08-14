import { formatSocialAuthorityResult } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { loadParticipantLive, parseParticipantLiveOptions } from "../src/dev/hodlxxi-participant-live-composition.mjs";

const NONE = "None";
const safeEvidence = (value) => typeof value === "string" && /operator/i.test(value) ? "Suppressed" : (value ?? NONE);

function appendText(document, parent, name, value, className) {
  const element = document.createElement(name);
  if (className) element.className = className;
  element.textContent = value;
  parent.append(element);
  return element;
}

export function bindDevParticipantPage(document, { parse = parseParticipantLiveOptions, load = loadParticipantLive, format = formatSocialAuthorityResult } = {}) {
  const form = document.querySelector("#dev-participant-form");
  const button = form.querySelector('button[type="submit"]');
  const input = (id) => document.querySelector(id);
  const fields = {
    subject: input("#participant-selected-subject"), authorityClass: input("#participant-authority-class"),
    authorityState: input("#participant-authority-state"), diagnostic: input("#participant-authority-diagnostic"),
    evidence: input("#participant-authority-evidence"), observedAt: input("#participant-authority-observed"),
    relay: input("#participant-relay"), profileState: input("#participant-profile-state"),
    profileName: input("#participant-profile-name"), notesState: input("#participant-notes-state"), notes: input("#participant-notes")
  };
  let active = false;

  const failAuthority = () => {
    fields.authorityClass.textContent = "Limited";
    fields.authorityState.textContent = "Fail-closed";
    fields.diagnostic.textContent = "unavailable";
    fields.evidence.textContent = NONE;
    fields.observedAt.textContent = NONE;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (active) return;
    let options;
    try {
      options = parse({
        origin: input("#participant-origin").value, relayUrl: input("#participant-relay-input").value,
        subject: input("#participant-subject").value, timeoutMs: input("#participant-timeout").value,
        noteLimit: input("#participant-note-limit").value
      });
    } catch {
      fields.subject.textContent = NONE;
      failAuthority();
      fields.profileState.textContent = "Profile unavailable";
      fields.notesState.textContent = "Relay unavailable";
      return;
    }

    active = true;
    button.disabled = true;
    fields.subject.textContent = options.subject;
    fields.relay.textContent = options.relayUrl;
    fields.authorityClass.textContent = "Limited";
    fields.authorityState.textContent = "Loading";
    fields.diagnostic.textContent = "loading";
    fields.evidence.textContent = NONE;
    fields.observedAt.textContent = NONE;
    fields.profileState.textContent = "Loading";
    fields.profileName.textContent = NONE;
    fields.notesState.textContent = "Loading";
    fields.notes.replaceChildren();
    try {
      const result = await load(options);
      if (result.authority.status === "fulfilled") {
        try {
          format(result.authority.value);
          const authority = result.authority.value;
          fields.authorityClass.textContent = authority.assertedIdentityClass === "full" ? "Full" : "Limited";
          fields.authorityState.textContent = authority.assertedIdentityClass === "full" ? "Externally asserted Full" : "Valid external Limited";
          fields.diagnostic.textContent = "asserted";
          fields.evidence.textContent = safeEvidence(authority.evidenceSource);
          fields.observedAt.textContent = authority.observedAt ?? NONE;
        } catch { failAuthority(); }
      } else failAuthority();

      if (result.profile.status === "fulfilled") {
        fields.profileState.textContent = result.profile.value ? "Profile available" : "Profile missing";
        fields.profileName.textContent = result.profile.value?.displayName ?? NONE;
      } else {
        fields.profileState.textContent = "Profile unavailable — relay unavailable";
        fields.profileName.textContent = NONE;
      }

      if (result.notes.status === "fulfilled") {
        fields.notesState.textContent = result.notes.value.length ? "Notes available" : "No public notes";
        for (const note of result.notes.value) {
          const card = document.createElement("article");
          card.className = "post-card dev-participant-note";
          appendText(document, card, "time", note.timestamp, "post-meta");
          appendText(document, card, "p", note.body.slice(0, 500), "post-body");
          fields.notes.append(card);
        }
      } else fields.notesState.textContent = "Relay unavailable";
    } catch {
      failAuthority();
      fields.profileState.textContent = "Profile unavailable — relay unavailable";
      fields.notesState.textContent = "Relay unavailable";
    } finally {
      active = false;
      button.disabled = false;
    }
  });
  return Object.freeze({ form });
}

if (typeof document !== "undefined") bindDevParticipantPage(document);
