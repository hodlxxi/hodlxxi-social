import { relationshipContext, visibilityDecision } from "../src/visibility.mjs";

export const groups = Object.freeze([
  Object.freeze({ id: "group-01", title: "Local Builders", description: "A synthetic space for product-shell notes.", memberIds: Object.freeze(["a".repeat(64), "b".repeat(64), "c".repeat(64)]), activity: "Today · Interface boundaries reviewed locally" }),
  Object.freeze({ id: "group-02", title: "Design Study", description: "A local fixture for small-screen layout discussion.", memberIds: Object.freeze(["b".repeat(64), "d".repeat(64)]), activity: "Yesterday · Mobile spacing explored locally" })
]);

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const restricted = (detail = "This local group is unavailable for the current viewer.") => `<article class="group-restricted"><strong>Group restricted</strong><p>${detail}</p></article>`;

export function groupAccess({ groupId, viewer, viewerStatus, participants, edges, items = groups }) {
  const group = items.find((item) => item.id === groupId);
  if (!group || !viewer || !group.memberIds.includes(viewer.id)) return Object.freeze({ visible: false, reason: "restricted" });
  const people = new Map(participants.map((person) => [person.id, person]));
  const members = group.memberIds.map((id) => {
    const person = people.get(id);
    if (!person) return Object.freeze({ visible: false });
    const decision = visibilityDecision({ viewerStatus, context: relationshipContext(viewer.id, person.id, edges), policy: "social" });
    return decision.visible ? Object.freeze({ visible: true, person }) : Object.freeze({ visible: false });
  });
  if (!members[group.memberIds.indexOf(viewer.id)]?.visible) return Object.freeze({ visible: false, reason: "restricted" });
  return Object.freeze({ visible: true, group, members: Object.freeze(members) });
}

export function visibleGroups(input) {
  return Object.freeze((input.items ?? groups).map((group) => groupAccess({ ...input, groupId: group.id })).filter((result) => result.visible));
}

function renderMembers(access) {
  return access.members.map((member) => member.visible
    ? `<li class="group-member"><span class="avatar" aria-hidden="true">${escapeHtml(member.person.displayName[0])}</span><strong>${escapeHtml(member.person.displayName)}</strong></li>`
    : `<li class="group-member restricted-member"><strong>Restricted participant</strong><span>Identity unavailable under visibility policy</span></li>`).join("");
}

export function renderGroups(input, selectedId) {
  const available = visibleGroups(input);
  const list = available.length ? available.map(({ group }) => `<a class="group-row${selectedId === group.id ? " selected" : ""}" href="#/groups/${group.id}"${selectedId === group.id ? ' aria-current="page"' : ""}><strong>${escapeHtml(group.title)}</strong><span>${group.memberIds.length} synthetic members</span><small>${escapeHtml(group.description)}</small></a>`).join("") : restricted("No local groups are available for this viewer.");
  let detail = `<section class="group-empty"><h2>Choose a group</h2><p>Select an accessible synthetic group from the local list.</p></section>`;
  if (selectedId) {
    const access = groupAccess({ ...input, groupId: selectedId });
    detail = access.visible ? `<section class="group-detail"><p class="eyebrow">Local group detail</p><h2>${escapeHtml(access.group.title)}</h2><p>${escapeHtml(access.group.description)}</p><dl><div><dt>Members</dt><dd>${access.group.memberIds.length} synthetic</dd></div><div><dt>Recent local activity</dt><dd>${escapeHtml(access.group.activity)}</dd></div></dl><h3>Visible members</h3><ul class="group-members">${renderMembers(access)}</ul></section>` : restricted();
  }
  return `<section class="groups-product"><div class="local-disclosure"><strong>Local group fixtures</strong><span>Read-only presentation state with no Nostr interoperability or group authority.</span></div><div class="split-surface"><aside class="surface-list" aria-label="Accessible local groups">${list}</aside><div class="surface-detail">${detail}</div></div><p class="notice">Group membership does not imply friendship, sponsor-trust, covenant status, or operator authority.</p></section>`;
}
