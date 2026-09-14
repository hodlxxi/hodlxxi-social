// Explicitly constructed only. Transient delivery proofs stay in this closure;
// only the Phase-1 non-extractable device CryptoKey uses IndexedDB persistence.
import { canonical, exact, parseClosedJson, SOCIAL_MOBILE_PREFIX, MOBILE_CSRF_HEADER, MOBILE_COMMANDS,
  validateCommand, validateMobileResponse, validateReceipt, inspectPhoneSource, unavailable } from "./social-mobile-protocol-v1.mjs";
import { createMessagingDeviceStore } from "./messaging-device-v128c1.mjs";
import { preparePhoneMessagingDevice, createDesktopPhoneApproval } from "./mobile-device-authorization-seams-v1.mjs";
import { METHODS, createMobileAuthorization, parsePairingQr, phoneExchangeCommitment, pairingPossessionProof,
  pairingComparisonCode, parseMobileEventRetry } from "./mobile-device-authorization-contract-v1.mjs";

export function createMobileBrowserApi({ enabled = false, fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  let csrf;
  async function post(path, body) {
    if (enabled !== true || typeof fetchImpl !== "function" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) unavailable();
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), timeoutMs);
    try {
      const response = await fetchImpl(path, { method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: { "Content-Type": "application/json", ...(csrf ? { [MOBILE_CSRF_HEADER]: csrf } : {}) }, body: canonical(body), signal: abort.signal });
      const text = await response.text();
      const value = parseClosedJson(text, { canonicalOnly: true });
      if (response.status !== 200) unavailable();
      return value;
    } finally { clearTimeout(timer); }
  }
  const api = {
    async connect() { const v = exact(await post(SOCIAL_MOBILE_PREFIX + "/context", {}), ["csrf"]); if (!/^[0-9a-f]{64}$/.test(v.csrf)) unavailable(); csrf = v.csrf; },
    async logout() {
      const v = exact(await post("/auth/logout", {}), ["authenticated", "logout"]);
      if (v.authenticated !== false || !["confirmed", "local-only"].includes(v.logout)) unavailable();
      return v;
    }
  };
  for (const [name, spec] of Object.entries(MOBILE_COMMANDS)) if (name !== "oauthInvalidate") api[name] = async (body) =>
    validateMobileResponse(name, await post(SOCIAL_MOBILE_PREFIX + "/" + spec.path, validateCommand(spec, body)));
  for (const name of ["issue", "recover"]) api[name] = async (body) => {
    const v = exact(await post(SOCIAL_MOBILE_PREFIX + "/session/" + name, body), ["authenticated", "subject", "receipt", "messaging"]);
    if (v.authenticated !== true || !/^[0-9a-f]{64}$/.test(v.subject) || v.messaging !== "not-ready") unavailable();
    validateReceipt(v.receipt); return Object.freeze(v);
  };
  return Object.freeze(api);
}

export function createPhoneMobileController({ enabled = false, api, store = createMessagingDeviceStore(),
  cryptoImpl = globalThis.crypto, CryptoKeyImpl = globalThis.CryptoKey, now = Date.now } = {}) {
  let pending, busy = false, stopped = false, terminal;
  const check = () => { if (enabled !== true || stopped) unavailable(); };
  const random = () => [...cryptoImpl.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
  async function run(fn) { check(); if (busy) unavailable(); busy = true; try { return await fn(); } finally { busy = false; } }
  const selectors = () => {
    if (!pending?.source) unavailable();
    return { pairingId: pending.offer.pairingId, revision: pending.offer.revision, authorizationDigest: pending.parsed.digest, verifier: pending.verifier };
  };
  const recoveryBody = () => ({ source: pending.source, qr: pending.qr, possessionProof: pending.possessionProof,
    verifier: pending.verifier, revision: pending.offer.revision });
  return Object.freeze({
    async scan(qr) { return run(async () => {
      if (pending?.proofLoss || pending && pending.qr !== qr) unavailable();
      if (!pending) {
        const offer = await api.qrOffer({ qr }); check();
        // Allocate deliveryKey independently before any possible issuance.
        pending = { offer, qr, verifier: random(), deliveryKey: random() };
        if (pending.verifier === pending.deliveryKey || pending.deliveryKey === parsePairingQr(qr).secret) unavailable();
      }
      if (!pending.source) {
        let record = await store.read(); check();
        // A key found after reload has no original transient proof ownership.
        // Only this controller's interrupted prepare may resume that key.
        if (record && !pending.keyIdentity) { pending.proofLoss = true; unavailable(); }
        if (!record && pending.keyIdentity) unavailable();
        let proposal;
        if (!record) {
          const ownedStore = { read: () => store.read(), create: (value) => {
            pending.keyIdentity = Object.fromEntries(["subject", "deviceId", "publicKey", "requestId", "pendingProposal"].map((k) => [k, value[k]]));
            return store.create(value);
          } };
          proposal = await preparePhoneMessagingDevice({ enabled, subject: pending.offer.subject, store: ownedStore, cryptoImpl, CryptoKeyImpl,
            contextStillCurrent: () => !stopped }); check();
          record = await store.read(); check();
        } else {
          if (Object.entries(pending.keyIdentity).some(([k, v]) => record[k] !== v)) unavailable();
          proposal = parseClosedJson(record.pendingProposal);
        }
        if (record.subject !== pending.offer.subject || record.deviceId !== proposal.deviceId || record.publicKey !== proposal.publicKey || record.requestId !== proposal.requestId) unavailable();
        pending.record = record;
        const issuedAt = new Date(Math.floor(now() / 1000) * 1000).toISOString().replace(".000Z", "Z");
        const content = canonical({ domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1", authorization: {
          schema: "hodlxxi.social_messaging_device_binding_authorization.v1", version: 1,
          bindingRecordSchema: "hodlxxi.social_messaging_device_binding_record.v1", bindingRecordVersion: 1,
          algorithm: "x25519-v1", bindingVersion: 1, subject: record.subject, deviceId: record.deviceId, publicKey: record.publicKey,
          operation: "register", priorBindingId: null, requestId: record.requestId, issuedAt, expiresAt: pending.offer.expiresAt,
          bindingValidFrom: issuedAt, bindingExpiresAt: pending.offer.expiresAt } });
        const context = Object.fromEntries(["pairingId", "secretCommitment", "desktopContext", "createdAt", "expiresAt"].map((k) => [k, pending.offer[k]]));
        context.exchangeCommitment = await phoneExchangeCommitment(pending.verifier, cryptoImpl); check();
        const source = await createMobileAuthorization(content, canonical(context), METHODS.qr,
          { subject: record.subject, proposal, now: Math.floor(now() / 1000), cryptoImpl }); check();
        const parsed = await inspectPhoneSource(source, cryptoImpl); check();
        const possessionProof = await pairingPossessionProof(parsePairingQr(qr).secret, parsed.digest, cryptoImpl); check();
        Object.assign(pending, { source, parsed, possessionProof });
      }
      const snapshot = await api.qrScan({ source: pending.source, qr, possessionProof: pending.possessionProof }); check();
      if (snapshot.source !== pending.source || snapshot.revision !== pending.offer.revision) unavailable();
      return Object.freeze({ comparisonCode: pairingComparisonCode(pending.parsed.digest), expiresAt: pending.offer.expiresAt,
        subject: pending.parsed.semantic.subject, status: snapshot.status });
    }); },
    async status() { return run(async () => { const s = await api.phoneStatus(selectors()); check();
      if (s.authorizationDigest !== pending.parsed.digest) unavailable(); terminal = s.status; return s; }); },
    async recover() { return run(async () => {
      selectors(); const status = await api.phoneRecover(recoveryBody()); check(); terminal = status.status;
      if (status.status !== "accepted") return status;
      // recover cannot create an absent issuance. The user may explicitly
      // complete the original delivery after reconciling acceptance.
      const result = await api.recover({ ...selectors(), deliveryKey: pending.deliveryKey }); check(); return result;
    }); },
    async complete() { return run(async () => {
      const status = await api.phoneRecover(recoveryBody()); check();
      if (status.status !== "accepted") unavailable();
      const result = await api.issue({ ...selectors(), deliveryKey: pending.deliveryKey }); check();
      if (result.subject !== pending.parsed.semantic.subject) unavailable(); return result;
    }); },
    async cleanupCancelled() { return run(async () => {
      const status = await api.phoneRecover(recoveryBody()); check();
      if (!["cancelled", "rejected"].includes(status.status) || status.authorizationDigest !== pending.parsed.digest) unavailable();
      await store.discardCancelledPending(pending.record); pending = undefined; terminal = undefined;
    }); },
    async logout() { stopped = true; return api.logout(); },
    state() { return Object.freeze({ pending: Boolean(pending), terminal, recovery: pending && !pending.proofLoss ? "original-proofs-in-memory" : "proofs-unavailable-new-login-required", messaging: "not-ready" }); }
  });
}

// Public signed event persistence only; no provider, verifier or deliveryKey.
export function createMobilePublicRetryStore(indexedDBImpl = globalThis.indexedDB) {
  async function access(id, value) {
    return new Promise((resolve, reject) => {
      const open = indexedDBImpl.open("hodlxxi-social-mobile-public-retry-v1", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("retry");
      open.onerror = open.onblocked = () => reject(new Error("public retry unavailable"));
      open.onsuccess = () => {
        const db = open.result, tx = db.transaction("retry", value === undefined ? "readonly" : "readwrite", { durability: "strict" });
        const store = tx.objectStore("retry"), get = store.get(id); let result;
        get.onsuccess = () => { result = get.result; if (value !== undefined) { if (result !== undefined && result !== value) tx.abort(); else store.put(value, id); } };
        tx.oncomplete = () => { db.close(); resolve(result); };
        tx.onabort = tx.onerror = () => { db.close(); reject(new Error("public retry unavailable")); };
      };
    });
  }
  return Object.freeze({ read: (id) => access(id), save: (id, value) => access(id, value) });
}

export function createDesktopMobileController({ enabled = false, api, subject, resolveProvider, retryStore = createMobilePublicRetryStore(),
  cryptoImpl = globalThis.crypto, now = Date.now } = {}) {
  let creation, snapshot, parsed, approval, retry;
  const check = () => { if (enabled !== true) unavailable(); };
  const selectors = () => { if (!creation) unavailable(); return { pairingId: creation.offer.pairingId, revision: creation.offer.revision }; };
  const inspect = async () => {
    check(); const result = await api.qrSnapshot(selectors()); snapshot = result;
    if (!result.source) return result;
    parsed = await inspectPhoneSource(result.source, cryptoImpl);
    if (parsed.semantic.subject !== subject || parsed.context.pairingId !== creation.offer.pairingId || result.revision !== creation.offer.revision) unavailable();
    return { status: result.status, comparisonCode: pairingComparisonCode(parsed.digest), expiresAt: parsed.context.expiresAt, subject };
  };
  return Object.freeze({
    async create() { check(); if (creation) unavailable(); creation = await api.qrCreate({}); if (creation.offer.subject !== subject) unavailable(); return creation; },
    inspect,
    async approve(comparisonCode) {
      check(); if (!parsed || approval) unavailable();
      const context = { subject, ...selectors(), transcriptDigest: parsed.digest };
      approval = createDesktopPhoneApproval({ enabled, getContext: () => context, cryptoImpl, now: () => Math.floor(now() / 1000), resolveProvider,
        claimApproval: async () => (await api.qrClaim({ ...selectors(), authorizationDigest: parsed.digest, humanCode: comparisonCode })).status === "approval-claimed",
        persistRetry: async (value) => { await retryStore.save(context.pairingId, value); retry = value; } });
      await approval.approve({ authorization: snapshot.source, comparisonCode });
      // The persisted Phase-1 retry wraps the event and source. M/qr/accept
      // consumes only the exact canonical signed event, as pinned UBID defines.
      return api.qrAccept({ ...selectors(), authorizationDigest: parsed.digest, proof: canonical(parseClosedJson(retry).signedEvent) });
    },
    async retryAcceptance() {
      check(); await inspect();
      retry = retry ?? await retryStore.read(creation.offer.pairingId);
      if (!retry) unavailable();
      const event = await parseMobileEventRetry(snapshot.source, retry, { subject, expectedMethod: METHODS.qr, now: parsed.semantic.issuedAt, cryptoImpl });
      return api.qrAccept({ ...selectors(), authorizationDigest: parsed.digest, proof: canonical(event) });
    },
    async close(status = "cancelled") { check(); approval?.cancel(); return api.qrClose({ pairingId: selectors().pairingId, status }); },
    async logout() { approval?.cancel(); return api.logout(); }
  });
}
