import { normalizePublicKey } from "../domain.mjs";
import { declareCapabilities } from "./adapter.mjs";
import { SocialCapability } from "./capabilities.mjs";

export class HodlxxiAuthorityReadAdapter {
  #transport;

  constructor(transport) {
    this.capabilities = declareCapabilities([SocialCapability.READ_EXTERNAL_AUTHORITY]);
    this.#transport = transport && typeof transport.readAssertion === "function" ? transport : undefined;
    Object.freeze(this);
  }

  readAssertion(subject) {
    try {
      return this.#transport?.readAssertion(normalizePublicKey(subject));
    } catch {
      return undefined;
    }
  }
}
