import {
  renderSecureMessagingPreview
} from "./preview.mjs";

const baseModel = Object.freeze({
  device: Object.freeze({
    label: "This browser - MacBook",
    state: "ready"
  }),
  conversations: Object.freeze([
    Object.freeze({
      id: "conversation-brother",
      person: Object.freeze({
        alias: "p_KHcJHzAgVKtH830W3gJGIg",
        label: "Brother",
        status: "full"
      }),
      timestamp: "18:22",
      unread: 0,
      messages: Object.freeze([
        Object.freeze({
          direction: "outgoing",
          body: "Hey! I am checking how our secure conversation will look.",
          time: "18:21",
          state: "opened"
        }),
        Object.freeze({
          direction: "incoming",
          body: "Looks good. The important part is that the server only sees ciphertext.",
          time: "18:22",
          state: "delivered"
        })
      ])
    }),
    Object.freeze({
      id: "conversation-alice",
      person: Object.freeze({
        alias: "p_7QmJ4xNrT8vL2eSa6dUc",
        label: "Alice",
        status: "full"
      }),
      timestamp: "Yesterday",
      unread: 2,
      messages: Object.freeze([
        Object.freeze({
          direction: "incoming",
          body: "See you tomorrow.",
          time: "Yesterday 20:14",
          state: "delivered"
        })
      ])
    }),
    Object.freeze({
      id: "conversation-private-alias",
      person: Object.freeze({
        alias: "p_R9m3WkU1cP7zQe4tYx",
        label: null,
        status: "full"
      }),
      timestamp: "Mon",
      unread: 0,
      messages: Object.freeze([
        Object.freeze({
          direction: "outgoing",
          body: "This card has no private label on this device, so the viewer-private alias is shown.",
          time: "Mon 09:40",
          state: "sent"
        })
      ])
    })
  ]),
  recipientCandidates: Object.freeze([
    Object.freeze({
      alias: "p_KHcJHzAgVKtH830W3gJGIg",
      label: "Brother",
      status: "full"
    }),
    Object.freeze({
      alias: "p_7QmJ4xNrT8vL2eSa6dUc",
      label: "Alice",
      status: "full"
    }),
    Object.freeze({
      alias: "p_N4d6rVp2Ls8wTa5cJq",
      label: "Sister",
      status: "full"
    })
  ]),
  selectedConversationId: "conversation-brother"
});

let selectedConversationId = baseModel.selectedConversationId;

const root = document.querySelector("#secure-messaging-preview");
const live = document.querySelector("#secure-preview-live");

const model = () => ({
  ...baseModel,
  selectedConversationId
});

const announce = (message) => {
  if (!live) return;
  live.textContent = message;
};

const render = () => {
  if (!root) return;
  root.innerHTML = renderSecureMessagingPreview(model());
};

const selectedRecipientLabel = (alias) =>
  baseModel.recipientCandidates.find((item) => item.alias === alias)?.label ?? alias;

root?.addEventListener("click", (event) => {
  const target = event.target instanceof Element
    ? event.target.closest("button")
    : null;
  if (!target) return;

  const conversationId = target.dataset.conversationId;
  if (conversationId) {
    selectedConversationId = conversationId;
    render();
    announce("Preview conversation selected. No network request was made.");
    return;
  }

  const action = target.dataset.previewAction;
  if (action === "new-message") {
    document.querySelector(".secure-new-message")?.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
    announce("New message preview opened. Recipient capability is not requested in this prototype.");
    return;
  }

  if (action === "select-recipient") {
    announce(
      `Selected ${selectedRecipientLabel(target.dataset.recipientAlias)} for preview only. No rc_ capability or crypto package was requested.`
    );
    return;
  }

  if (action === "manage-device" || action === "setup-device") {
    announce("Device controls are visual only in V1.28B. No key was generated, read, stored, or uploaded.");
  }
});

root?.addEventListener("submit", (event) => {
  if (!(event.target instanceof HTMLFormElement)) return;
  if (event.target.dataset.previewForm !== "message") return;
  event.preventDefault();
  announce("Send is intentionally inert. No plaintext, ciphertext, key, or message left this page.");
});

render();
