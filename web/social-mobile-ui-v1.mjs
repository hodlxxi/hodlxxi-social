import { createMobileBrowserApi, createPhoneMobileController, createDesktopMobileController } from "./social-mobile-browser-v1.mjs";
// Opt-in mount only; no entrypoint/discovery/default runtime import.
export async function mountSocialMobileAuthorization({ enabled = false, root, role, subject, resolveProvider, ...dependencies } = {}) {
  if (enabled !== true) return undefined;
  if (!root || !["desktop", "phone"].includes(role)) throw new TypeError("invalid mobile UI");
  const api = createMobileBrowserApi({ ...dependencies, enabled }); await api.connect();
  const controller = role === "phone" ? createPhoneMobileController({ ...dependencies, enabled, api })
    : createDesktopMobileController({ ...dependencies, enabled, api, subject, resolveProvider });
  const doc = root.ownerDocument, input = doc.createElement("input"), output = doc.createElement("p");
  input.type = "text"; input.autocomplete = "off";
  input.setAttribute("aria-label", role === "phone" ? "Original pairing locator" : "Comparison code shown on phone");
  const note = doc.createElement("p");
  note.textContent = "This login ends at the original pairing deadline, within five minutes of creation. Messaging is not ready. Keep this page open: lost delivery proofs require a new login. QR camera scanning is not provided by this view.";
  root.replaceChildren(note, input, output);
  const actions = role === "phone" ? [["Scan locator", () => { const qr = input.value; input.value = ""; return controller.scan(qr); }], ["Check status", () => controller.status()],
    ["Complete login", () => controller.complete()], ["Recover delivery", () => controller.recover()], ["Clean up cancelled proposal", () => controller.cleanupCancelled()]]
    : [["Create pairing", async () => { const c = await controller.create(); output.textContent = "Pairing locator (share privately): " + c.qr; return { expiresAt: c.offer.expiresAt }; }],
      ["Inspect phone", () => controller.inspect()], ["Approve matching code", () => controller.approve(input.value)], ["Retry saved approval", () => controller.retryAcceptance()], ["Cancel pairing", () => controller.close()]];
  actions.push(["Log out", () => controller.logout()]);
  for (const [label, action] of actions) {
    const button = doc.createElement("button"); button.textContent = label;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { const result = await action(); if (label !== "Create pairing") output.textContent = JSON.stringify(result ?? { status: "done" }); }
      catch { output.textContent = label === "Log out" ? "Local access denied; upstream logout is unconfirmed. Retry logout." : "Unavailable. Preserve this page and pending key; check status or recover the original delivery."; }
      finally { button.disabled = false; }
    }); root.append(button);
  }
  return controller;
}
