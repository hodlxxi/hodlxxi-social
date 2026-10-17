// Explicit native V2 presentation owner. Not installed by the active V1 BFF.
import { types } from "node:util";
import { exact, canonical, hex64 } from "../../web/social-mobile-protocol-v1.mjs";
import { createSessionStore } from "./social-oauth-memory.mjs";
import { validateNativeV2SessionResponse } from "./ubid-social-session-v2-client.mjs";

export const SOCIAL_NATIVE_V2_SESSION_MANAGER_ENABLED = false;
const fail = () => { throw new TypeError("native v2 session unavailable"); };
const own = (value, fields) => { try { if (types.isProxy(value)) fail(); return exact(value, fields); } catch { fail(); } };
const native = (value) => value && !types.isProxy(value) && Object.getOwnPropertyDescriptor(value, "kind")?.value === "ubid-mobile-v2";
const receiptFor = (record) => Object.freeze({ schema: "hodlxxi.social_session_issuance.v2", version: 2,
  issuanceId: record.issuanceId, socialSessionIssuanceRevision: record.issuanceRevision,
  acceptanceId: record.acceptanceId, issuedAt: record.issuedAt, expiresAt: record.expiresAt });
const sameReceipt = (a, b) => canonical(a) === canonical(b);

export function createNativeV2SessionStore(options) {
  const args = own(options, ["ttlSeconds", "capacity", "now"]);
  return createSessionStore({ ...args, nativeV2Enabled: true });
}

export function createNativeV2SessionManager(options) {
  try {
    if (options === undefined) return undefined;
    if (types.isProxy(options)) fail();
    const enabled = Object.getOwnPropertyDescriptor(options, "enabled");
    if (enabled === undefined || Object.hasOwn(enabled, "value") && enabled.value === false) return undefined;
    const cfg = own(options, ["enabled", "client", "store", "capacity", "now", "random"]);
    if (cfg.enabled !== true || !Number.isSafeInteger(cfg.capacity) || cfg.capacity < 1 ||
        typeof cfg.now !== "function" || typeof cfg.random !== "function" ||
        !["resolve", "revoke"].every((name) => typeof cfg.client?.[name] === "function") ||
        !["create", "get", "getForLogout", "getLogoutState", "beginLogout"].every((name) => typeof cfg.store?.[name] === "function")) fail();
    const aliases = new Map(), locks = new Map();
    let previous = -1, pending = 0;
    const now = () => { const at = cfg.now(); if (!Number.isSafeInteger(at) || at < 0 || at < previous) fail(); previous = at; return at; };
    const sweep = () => { now(); for (const [issuance, id] of aliases) if (!cfg.store.getForLogout(id)) aliases.delete(issuance); };
    const serialize = async (issuance, work) => {
      if (pending >= cfg.capacity) fail();
      pending++;
      const before = locks.get(issuance) ?? Promise.resolve();
      let release; const tail = new Promise((resolve) => { release = resolve; });
      locks.set(issuance, tail);
      try { await before; return await work(); }
      finally { pending--; release(); if (locks.get(issuance) === tail) locks.delete(issuance); }
    };
    const checked = async (record) => {
      if (!native(record)) fail();
      const response = validateNativeV2SessionResponse(await cfg.client.resolve({
        body: { issuanceId: record.issuanceId }, viewerAccessToken: record.viewerAccessToken,
      }), now(), { resolve: true });
      if (!response.currentActive || response.subject !== record.subject || !sameReceipt(response.receipt, receiptFor(record))) fail();
      return record;
    };
    const revoke = async (record) => {
      const value = own(await cfg.client.revoke({ body: { issuanceId: record.issuanceId },
        viewerAccessToken: record.viewerAccessToken }), ["schema", "version", "issuanceId", "status"]);
      if (value.schema !== "hodlxxi.social_session_revocation.v2" || value.version !== 2 ||
          value.issuanceId !== record.issuanceId || value.status !== "revoked") fail();
      return true;
    };
    const capabilityRead = async (id) => {
      try {
        const original = cfg.store.get(id); if (!native(original)) return null;
        await checked(original);
        if (cfg.store.get(id) !== original || now() >= original.expiresAt) return null;
        return original;
      } catch { return null; }
    };
    const read = async (id) => { const value = await capabilityRead(id); return value ? Object.freeze({
      subject: value.subject, receipt: receiptFor(value), expiresAt: value.expiresAt,
    }) : null; };
    const install = async (source, expectations) => {
      try {
        const expected = own(expectations, ["subject", "acceptanceId", "maximumExpiresAt", "stillCurrent"]);
        const result = validateNativeV2SessionResponse(source, now());
        if (!hex64(expected.subject) || !hex64(expected.acceptanceId) || typeof expected.stillCurrent !== "function" ||
            !Number.isSafeInteger(expected.maximumExpiresAt) || !result.currentActive || result.subject !== expected.subject ||
            result.receipt.acceptanceId !== expected.acceptanceId || result.receipt.expiresAt > expected.maximumExpiresAt) fail();
        const record = Object.freeze({ kind: "ubid-mobile-v2", subject: result.subject,
          viewerAccessToken: result.viewerAccessToken, issuanceId: result.receipt.issuanceId,
          issuanceRevision: result.receipt.socialSessionIssuanceRevision, acceptanceId: result.receipt.acceptanceId,
          issuedAt: result.receipt.issuedAt, expiresAt: result.receipt.expiresAt });
        return await serialize(record.issuanceId, async () => {
          sweep();
          if (expected.stillCurrent() !== true) fail();
          await checked(record);
          if (expected.stillCurrent() !== true || now() >= record.expiresAt) fail();
          let id = aliases.get(record.issuanceId);
          if (id !== undefined) {
            const original = cfg.store.get(id);
            if (!native(original) || canonical(original) !== canonical(record)) fail();
          } else {
            if (aliases.size >= cfg.capacity) fail();
            const entropy = cfg.random(32);
            if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 32) fail();
            id = Buffer.from(entropy).toString("base64url");
            if (!cfg.store.create(id, record)) fail();
            aliases.set(record.issuanceId, id);
          }
          if (expected.stillCurrent() !== true) { cfg.store.beginLogout(id); fail(); }
          const maxAge = Math.floor((record.expiresAt - now()) / 1000);
          if (maxAge < 1) { cfg.store.beginLogout(id); fail(); }
          return Object.freeze({ id, maxAge,
            subject: record.subject, receipt: receiptFor(record) });
        });
      } catch { fail(); }
    };
    const logout = async (id) => {
      try {
        const record = cfg.store.getForLogout(id); if (!native(record)) fail();
        // Deny locally before any await, including lock-capacity failures.
        const state = cfg.store.beginLogout(id); if (!state) fail();
        return await serialize(record.issuanceId, async () => {
          if (cfg.store.getLogoutState(id) !== state) fail();
          if (!state.confirmed) { await revoke(record); state.confirmed = true; }
          return true;
        });
      } catch { fail(); }
    };
    const cancelUninstalled = async (source) => {
      try {
        const original = own(source, ["receipt", "subject", "currentActive", "viewerAccessToken"]);
        const rawReceipt = own(original.receipt, ["schema", "version", "issuanceId", "socialSessionIssuanceRevision", "acceptanceId", "issuedAt", "expiresAt"]);
        // Validate the retained original delivery only for exact cancellation.
        // This path never calls install, reads current authority or grants a cookie.
        const result = validateNativeV2SessionResponse(original, rawReceipt.issuedAt);
        if (!result.currentActive) fail();
        return await serialize(result.receipt.issuanceId, async () => {
          const id = aliases.get(result.receipt.issuanceId);
          if (id) cfg.store.beginLogout(id);
          return revoke({ issuanceId: result.receipt.issuanceId, viewerAccessToken: result.viewerAccessToken });
        });
      } catch { fail(); }
    };
    return Object.freeze({ install, read, capabilityRead, logout, cancelUninstalled });
  } catch { fail(); }
}
