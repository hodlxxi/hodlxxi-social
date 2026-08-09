import { loadDevLiveSocial } from "../src/dev/live-social-composition.mjs";

export const NOTE_CONTENT_LIMIT = 500;

const failureState = (error) => {
  const message = error instanceof Error ? error.message : "live read failed";
  if (/relay URL|explicit relay|event limit/i.test(message)) return "Invalid relay or read limit";
  if (/timed out|timeout/i.test(message)) return "Relay read timed out";
  if (/malformed|message must be text|unsupported Nostr relay frame|wrong subscription/i.test(message)) return "Malformed relay data";
  if (error instanceof TypeError) return "Relay event validation rejected the response";
  return "Relay connection/read failed";
};

function appendText(document, parent, name, value, className) {
  const element = document.createElement(name);
  if (className) element.className = className;
  element.textContent = value;
  parent.append(element);
  return element;
}

export function renderAcceptedNotes(document, container, data) {
  container.replaceChildren();
  const participants = new Map(data.participants.map((person) => [person.id, person]));
  for (const note of data.notes) {
    const card = document.createElement("article");
    card.className = "post-card dev-live-note";
    const author = participants.get(note.authorId);
    appendText(document, card, "strong", author?.publicKey ?? note.authorId, "key");
    const time = appendText(document, card, "time", note.timestamp, "post-meta");
    time.dateTime = note.timestamp;
    appendText(document, card, "p", note.body.slice(0, NOTE_CONTENT_LIMIT), "post-body");
    container.append(card);
  }
}

export function bindDevLivePage(document, { readLive = loadDevLiveSocial } = {}) {
  const form = document.querySelector("#dev-live-form");
  const relayInput = document.querySelector("#relay-url");
  const limitInput = document.querySelector("#event-limit");
  const button = form.querySelector('button[type="submit"]');
  const status = document.querySelector("#dev-live-status");
  const selectedRelay = document.querySelector("#dev-live-relay");
  const feed = document.querySelector("#dev-live-feed");
  let reading = false;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (reading) return;
    reading = true;
    button.disabled = true;
    feed.replaceChildren();
    selectedRelay.textContent = relayInput.value || "None";
    status.textContent = "Connecting for one bounded read…";
    try {
      const result = await readLive({ relayUrl: relayInput.value, limit: limitInput.value });
      selectedRelay.textContent = result.relayUrl;
      renderAcceptedNotes(document, feed, result.data);
      status.textContent = result.data.notes.length === 0
        ? "Read completed: zero accepted public notes."
        : `Read completed: ${result.data.notes.length} accepted public note${result.data.notes.length === 1 ? "" : "s"}.`;
    } catch (error) {
      feed.replaceChildren();
      status.textContent = `${failureState(error)}. No synthetic fallback is shown.`;
    } finally {
      reading = false;
      button.disabled = false;
    }
  });
  return Object.freeze({ form, feed });
}

if (typeof document !== "undefined") bindDevLivePage(document);
