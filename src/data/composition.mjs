import { createSocialDataService } from "./service.mjs";

export function createComposedSocialDataService({ socialAdapter, authorityAdapter, now = 100 } = {}) {
  if (!socialAdapter) throw new TypeError("social adapter must be explicitly selected");
  return createSocialDataService(socialAdapter, { authorityAdapter, now });
}
