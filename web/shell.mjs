const item = (page, label, group, mobile = false) => Object.freeze({ page, label, group, mobile });

export const navigationModel = Object.freeze([
  item("home", "Home", "Core", true), item("circle", "My Circle", "Core", true), item("search", "Search", "Core", true), item("discover", "Discover", "Core"),
  item("friends", "Friends", "Social"), item("discovery", "Friends of Friends", "Social"), item("messages", "Messages", "Social", true), item("groups", "Groups", "Social"),
  item("notifications", "Notifications", "Updates"), item("activity", "Activity", "Updates"),
  item("profile", "Profile", "Identity & trust", true), item("trust", "Trust", "Identity & trust")
]);

const routePaths = Object.freeze({ home: "/home", circle: "/circle", search: "/search", discover: "/discover", friends: "/friends", discovery: "/friends-of-friends", messages: "/messages", groups: "/groups", notifications: "/notifications", activity: "/activity", trust: "/trust" });
const routePath = (page, viewerId) => page === "profile" ? `#/profile/${viewerId}` : `#${routePaths[page] ?? "/not-found"}`;
const isActive = (route, page) => route.page === page;
const badge = (page, unread) => page === "notifications" ? `<span class="nav-badge" aria-label="${unread} unread local notifications">${unread}</span>` : "";
const link = (entry, route, viewerId, unread) => `<a href="${routePath(entry.page, viewerId)}"${isActive(route, entry.page) ? ' aria-current="page"' : ""}>${entry.label}${badge(entry.page, unread)}</a>`;

export function renderDesktopNavigation(route, viewerId, unread = 0) {
  const groups = [...new Set(navigationModel.map(({ group }) => group))];
  return `<nav class="nav-links" aria-label="Primary">${groups.map((group) => `<section class="nav-group"><h2>${group}</h2>${navigationModel.filter((entry) => entry.group === group).map((entry) => link(entry, route, viewerId, unread)).join("")}</section>`).join("")}</nav>`;
}

export function renderMobileNavigation(route, viewerId, unread = 0) {
  const primary = navigationModel.filter(({ mobile }) => mobile);
  const secondary = navigationModel.filter(({ mobile }) => !mobile);
  const secondaryActive = secondary.some(({ page }) => isActive(route, page));
  return `<nav class="mobile-nav" aria-label="Mobile primary">${primary.map((entry) => link(entry, route, viewerId, unread)).join("")}<details class="mobile-more"${secondaryActive ? " open" : ""}><summary${secondaryActive ? ' aria-current="page"' : ""}>More${badge("notifications", unread)}</summary><div class="mobile-more-menu" role="navigation" aria-label="More destinations">${secondary.map((entry) => link(entry, route, viewerId, unread)).join("")}</div></details></nav>`;
}

export function renderNavigation(route, viewerId, className = "nav-links", unread = 0) {
  return className === "mobile-nav" ? renderMobileNavigation(route, viewerId, unread) : renderDesktopNavigation(route, viewerId, unread);
}
