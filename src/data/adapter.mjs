import { ALL_SOCIAL_CAPABILITIES } from "./capabilities.mjs";

const known = new Set(ALL_SOCIAL_CAPABILITIES);

export class UnsupportedCapabilityError extends Error {
  constructor(capability) {
    super(`social adapter capability unavailable: ${capability}`);
    this.name = "UnsupportedCapabilityError";
  }
}

export function declareCapabilities(values) {
  if (!Array.isArray(values) || values.some((value) => !known.has(value))) throw new TypeError("adapter capabilities must be an explicit supported list");
  return Object.freeze([...new Set(values)]);
}

export function requireCapability(adapter, capability) {
  if (!adapter || !Array.isArray(adapter.capabilities) || !adapter.capabilities.includes(capability)) throw new UnsupportedCapabilityError(capability);
}

export function readFromAdapter(adapter, capability, method, ...args) {
  requireCapability(adapter, capability);
  if (typeof adapter[method] !== "function") throw new TypeError(`adapter is missing declared operation: ${method}`);
  return adapter[method](...args);
}
