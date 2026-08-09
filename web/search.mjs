import { relationshipContext, visibilityDecision } from "../src/visibility.mjs";
import { visibleFeed } from "./feed.mjs";
import { visibleGroups } from "./groups.mjs";
import { renderEmptyState, renderUnavailableState } from "./components.mjs";

const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const shortKey = (key) => `${key.slice(0, 8)}…${key.slice(-6)}`;
const secretLike = /(?:^|[^0-9a-f])[0-9a-f]{64}(?=$|[^0-9a-f])/i;

export function normalizeQuery(value) {
  if (typeof value !== "string") return "";
  const prepared = value.normalize("NFKC").replace(/\s+/g, " ").trim().toLowerCase();
  if (secretLike.test(prepared) || /[\u0000-\u001f\u007f]/.test(prepared)) return "";
  return prepared.slice(0, 120);
}

export function parseSearchQuery(path = "") {
  if (typeof path !== "string") return Object.freeze({ query: "", valid: false });
  const marker = path.indexOf("?");
  if (marker < 0) return Object.freeze({ query: "", valid: true });
  try {
    const encoded = path.slice(marker + 1);
    decodeURIComponent(encoded.replace(/\+/g, " "));
    const params = new URLSearchParams(encoded);
    const raw = params.get("q") ?? "";
    const query = normalizeQuery(raw);
    return Object.freeze({ query, valid: !raw || Boolean(query) });
  } catch {
    return Object.freeze({ query: "", valid: false });
  }
}

function rank(text, key, query) {
  if (text === query) return 0;
  if (text.startsWith(query)) return 1;
  if (key?.startsWith(query)) return 2;
  return text.includes(query) ? 3 : -1;
}

const stable = (items) => Object.freeze(items.sort((a, b) => a.rank - b.rank || a.id.localeCompare(b.id)).map(({ rank: _rank, ...item }) => Object.freeze(item)));

export function searchPeople(input, queryValue) {
  const query = normalizeQuery(queryValue);
  if (!query || !input.viewer) return Object.freeze([]);
  const permitted = input.participants.filter((person) => visibilityDecision({ viewerStatus: input.viewerStatus, context: relationshipContext(input.viewer.id, person.id, input.edges), policy: "social" }).visible);
  return stable(permitted.flatMap((person) => {
    const score = rank(normalizeQuery(person.displayName), person.publicKey.toLowerCase(), query);
    return score < 0 ? [] : [{ id: person.id, rank: score, person }];
  }));
}

export function searchPosts(input, queryValue) {
  const query = normalizeQuery(queryValue);
  if (!query) return Object.freeze([]);
  const people = new Map(input.participants.map((person) => [person.id, person]));
  return stable(visibleFeed(input).flatMap((post) => {
    const author = people.get(post.authorId);
    const text = `${author?.displayName ?? ""} ${post.body ?? ""} ${post.timestamp ?? ""}`;
    const score = rank(normalizeQuery(text), undefined, query);
    return score < 0 ? [] : [{ id: post.id, rank: score, post, author }];
  }));
}

export function searchGroups(input, queryValue) {
  const query = normalizeQuery(queryValue);
  if (!query) return Object.freeze([]);
  return stable(visibleGroups(input).flatMap(({ group }) => {
    const score = rank(normalizeQuery(`${group.title} ${group.description}`), undefined, query);
    return score < 0 ? [] : [{ id: group.id, rank: score, group }];
  }));
}

export function searchAll(input, queryValue) {
  const query = normalizeQuery(queryValue);
  return Object.freeze({ query, people: searchPeople(input, query), posts: searchPosts(input, query), groups: searchGroups(input, query) });
}

function section(title, items, render) {
  return `<section class="search-group"><header><h2>${title}</h2><span>${items.length}</span></header>${items.length ? `<div class="search-cards">${items.map(render).join("")}</div>` : '<p class="search-none">No matches in this category.</p>'}</section>`;
}

export function renderSearch(input, queryValue, queryValid = true) {
  const results = searchAll(input, queryValue);
  const form = `<form id="local-search" class="search-bar"><label class="sr-only" for="search-query">Search local synthetic content</label><input id="search-query" name="q" value="${escapeHtml(results.query)}" maxlength="120" autocomplete="off" placeholder="Search people, posts, and groups"><button type="submit">Search</button>${results.query ? '<a href="#/search" aria-label="Clear search">Clear</a>' : ""}</form>`;
  if (!queryValid) return `<section class="search-product">${form}${renderUnavailableState("search")}</section>`;
  if (!results.query) return `<section class="search-product">${form}${renderEmptyState("search")}</section>`;
  const count = results.people.length + results.posts.length + results.groups.length;
  if (!count) return `<section class="search-product">${form}${renderEmptyState("search-results")}</section>`;
  return `<section class="search-product">${form}<p class="search-summary">${count} permitted local result${count === 1 ? "" : "s"}</p><div class="search-results">${section("People", results.people, ({ person }) => `<a class="search-card search-person" href="#/profile/${person.id}"><span class="avatar" aria-hidden="true">${escapeHtml(person.displayName[0])}</span><span><strong>${escapeHtml(person.displayName)}</strong><small>${shortKey(person.publicKey)}</small></span></a>`)}${section("Posts", results.posts, ({ post, author }) => `<a class="search-card" href="#/home"><strong>${escapeHtml(author.displayName)}</strong><p>${escapeHtml(post.body)}</p><small>${escapeHtml(post.timestamp)}</small></a>`)}${section("Groups", results.groups, ({ group }) => `<a class="search-card" href="#/groups/${group.id}"><strong>${escapeHtml(group.title)}</strong><p>${escapeHtml(group.description)}</p><small>Accessible synthetic group</small></a>`)}</div><p class="notice">Results use local fixture visibility only. They are not trust, reputation, or popularity rankings.</p></section>`;
}
