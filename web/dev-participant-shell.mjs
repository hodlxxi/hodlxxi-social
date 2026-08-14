import { loadParticipantLive, parseParticipantLiveOptions } from "../src/dev/hodlxxi-participant-live-composition.mjs";
import { createParticipantShellSnapshot } from "../src/dev/hodlxxi-participant-shell-snapshot.mjs";
import { isCanonicalNip07PublicKey, NIP07_SELECTION_STATE, selectNip07PublicKey } from "../src/dev/nip07-public-key-selector.mjs";
import { renderFeed, renderNavigation, renderProfile, resolveViewer } from "./app.mjs";
import { renderPageFrame } from "./components.mjs";

const setMarkup = (target, markup, kind) => {
  target.innerHTML = markup;
  for (const button of target.querySelectorAll?.("button") ?? []) button.remove();
  if (kind === "feed") {
    for (const actions of target.querySelectorAll?.(".post-actions") ?? []) actions.remove();
    for (const meta of target.querySelectorAll?.(".post-meta") ?? []) meta.textContent = meta.textContent.replace(/ · synthetic fixture$/, " · public Nostr source");
    const emptyTitle = target.querySelector?.(".ui-state strong");
    const emptyDetail = target.querySelector?.(".ui-state .meta");
    if (emptyTitle) emptyTitle.textContent = "No public notes";
    if (emptyDetail) emptyDetail.textContent = "No bounded normalized public Nostr notes were returned for this selected key.";
  }
  if (kind === "profile") {
    const trust = target.querySelector?.(".trust-section p:not(.notice)");
    if (trust) trust.textContent = "No sponsor-trust relationships in this read-only snapshot";
  }
};

export function bindParticipantShell(document, { parse = parseParticipantLiveOptions, load = loadParticipantLive, map = createParticipantShellSnapshot, selectKey = selectNip07PublicKey, resolveProvider = () => globalThis.window?.nostr } = {}) {
  const form = document.querySelector("#participant-shell-form");
  const button = form.querySelector('button[type="submit"]');
  const selectionButton = document.querySelector("#shell-select-extension-key");
  const field = (id) => document.querySelector(id);
  const selected = field("#shell-selected-key");
  const selectionState = field("#shell-extension-state");
  const freshness = field("#shell-freshness");
  const profileState = field("#shell-profile-state");
  const feedState = field("#shell-feed-state");
  const profileTarget = field("#shell-profile");
  const feedTarget = field("#shell-feed");
  const navigationTarget = field("#shell-navigation");
  let active = false;
  let selecting = false;
  const clearRendered = () => {
    navigationTarget.innerHTML = "";
    setMarkup(profileTarget, renderPageFrame({ eyebrow: "Read-only participant", title: "Profile unavailable", content: '<article class="ui-state ui-state-unavailable"><strong>No current profile result</strong><p class="meta">The latest submission did not produce a renderable snapshot.</p></article>' }), "profile");
    setMarkup(feedTarget, renderPageFrame({ eyebrow: "Public Nostr source", title: "Public feed unavailable", content: '<article class="ui-state ui-state-unavailable"><strong>No current public-note result</strong><p class="meta">The latest submission did not produce a renderable snapshot.</p></article>' }), "feed");
  };

  selectionButton.addEventListener("click", async () => {
    if (selecting) return;
    const manual = field("#shell-subject").value;
    if (manual !== "" && !isCanonicalNip07PublicKey(manual)) {
      selectionState.textContent = "Invalid manual subject";
      return;
    }
    selecting = true;
    selectionButton.disabled = true;
    selectionState.textContent = "Selecting";
    try {
      const result = await selectKey({ resolveProvider });
      if (result?.state !== NIP07_SELECTION_STATE.selected || !isCanonicalNip07PublicKey(result.publicKey)) {
        selectionState.textContent = result?.state === NIP07_SELECTION_STATE.invalid ? NIP07_SELECTION_STATE.invalid : NIP07_SELECTION_STATE.unavailable;
        return;
      }
      if (manual === "") {
        field("#shell-subject").value = result.publicKey;
        selectionState.textContent = NIP07_SELECTION_STATE.selected;
      } else if (manual !== result.publicKey) {
        selectionState.textContent = "Subject mismatch";
      } else {
        selectionState.textContent = "Extension key selected — exact match";
      }
    } catch {
      selectionState.textContent = NIP07_SELECTION_STATE.unavailable;
    } finally {
      selecting = false;
      selectionButton.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (active) return;
    let options;
    try {
      options = parse({ origin: field("#shell-origin").value, relayUrl: field("#shell-relay").value, subject: field("#shell-subject").value, timeoutMs: field("#shell-timeout").value, noteLimit: field("#shell-note-limit").value });
    } catch {
      selected.textContent = "None";
      freshness.textContent = "Invalid explicit inputs — no reads";
      profileState.textContent = "Not loaded";
      feedState.textContent = "Not loaded";
      return;
    }
    active = true;
    button.disabled = true;
    selected.textContent = options.subject;
    freshness.textContent = "Reading once";
    profileState.textContent = "Loading";
    feedState.textContent = "Loading";
    clearRendered();
    try {
      const result = await load(options);
      const snapshot = map(result);
      const viewer = resolveViewer(snapshot.currentViewerId, snapshot);
      const common = { viewer, viewerStatus: snapshot.statuses[snapshot.currentViewerId], ...snapshot };
      setMarkup(navigationTarget, renderNavigation({ page: "home", path: "/home" }, snapshot.currentViewerId), "navigation");
      for (const link of navigationTarget.querySelectorAll?.("a") ?? []) if (!/^(Home|Profile)$/.test(link.textContent.trim())) link.remove();
      setMarkup(profileTarget, renderPageFrame({ eyebrow: "HODLXXI authority + public Nostr", title: "Participant profile", content: renderProfile(common) }), "profile");
      setMarkup(feedTarget, renderPageFrame({ eyebrow: "Public Nostr source", title: "Home / Public feed", content: renderFeed(common) }), "feed");
      profileState.textContent = snapshot.profileAvailable ? "Normalized public profile" : (result.profile.status === "rejected" ? "Profile unavailable" : "Profile unavailable — public-key-only identity");
      feedState.textContent = result.notes.status === "fulfilled" ? (snapshot.notes.length ? `${snapshot.notes.length} normalized public note${snapshot.notes.length === 1 ? "" : "s"}` : "No public notes") : "Public feed unavailable";
      const observedAt = result.authority.status === "fulfilled" ? result.authority.value?.observedAt : null;
      const safeObservedAt = snapshot.externalAssertions[snapshot.currentViewerId].valid && typeof observedAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00$/.test(observedAt);
      freshness.textContent = safeObservedAt ? observedAt : "One-shot result / authority freshness unavailable";
    } catch {
      freshness.textContent = "Read unavailable — Limited fail-closed";
      profileState.textContent = "Profile unavailable";
      feedState.textContent = "Public feed unavailable";
    } finally {
      active = false;
      button.disabled = false;
    }
  });
  return Object.freeze({ form, selectionButton });
}

if (typeof document !== "undefined") bindParticipantShell(document);
