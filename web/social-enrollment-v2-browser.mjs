// Opt-in registration controller. Private CryptoKeys stay in the existing IDB boundary.
import { canonical, exact, parseClosedJson } from "./social-mobile-protocol-v1.mjs";
import { createMessagingDeviceStore } from "./messaging-device-v128c1.mjs";
import { preparePhoneMessagingDevice } from "./mobile-device-authorization-seams-v1.mjs";
import { createMessagingDeviceEd25519KeyV2 } from "./messaging-device-ed25519-key-v2.mjs";
import { parsePairingQr } from "./mobile-device-authorization-contract-v1.mjs";
import { acceptanceIdV2, approvalUnsignedEventV2, authorizationDigestV2, createApprovalEventV2,
  createAuthorizationEnvelopeV2, createBoundPreEnrollmentV2, parseAuthorizationEnvelopeV2,
  phoneExchangeCommitmentV2, pairingPossessionProofV2, validateAuthorizationTimeV2 }
  from "./mobile-device-authorization-contract-v2.mjs";
import { preEnrollmentComparisonCode } from "./mobile-device-authorization-seams-v2.mjs";

const PREFIX = "/auth/enrollment/v2";
const fail = () => { throw new TypeError("device registration unavailable"); };
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

// complete includes sequential reserve and finalize; it never renews authority.
export const ENROLLMENT_COMPLETE_TIMEOUT_MS = 60000;

export function createEnrollmentBrowserApi({ fetchImpl = globalThis.fetch, timeoutMs } = {}) {
  const ordinaryTimeout = timeoutMs === undefined ? 30000 : timeoutMs;
  const completeTimeout = timeoutMs === undefined ? ENROLLMENT_COMPLETE_TIMEOUT_MS : timeoutMs;
  let csrf;
  return Object.freeze({
    async call(command, body) {
      if (!/^[a-z]+$/.test(command) || typeof fetchImpl !== "function" ||
          !Number.isSafeInteger(ordinaryTimeout) || ordinaryTimeout < 1 || ordinaryTimeout > 30000) fail();
      const abort = new AbortController(), timer = setTimeout(() => abort.abort(),
        command === "complete" ? completeTimeout : ordinaryTimeout);
      try {
        const response = await fetchImpl(PREFIX + "/" + command, { method: "POST", credentials: "same-origin",
          redirect: "error", cache: "no-store", signal: abort.signal,
          headers: { "Content-Type": "application/json", ...(csrf ? { "x-hodlxxi-enrollment-csrf": csrf } : {}) }, body: canonical(body) });
        if (response.status !== 200 || !/^application\/json(?:;.*)?$/i.test(response.headers.get("content-type") ?? "")) fail();
        const value = parseClosedJson(await response.text(), { maximum: 65536, depth: 4 });
        if (command === "context") {
          const checked = exact(value, ["csrf"]); if (!/^[0-9a-f]{64}$/.test(checked.csrf)) fail(); csrf = checked.csrf;
        }
        return value;
      } finally { clearTimeout(timer); }
    },
  });
}

export function createDesktopApprovalStore(indexedDBImpl = globalThis.indexedDB) {
  const access = (id, transform) => new Promise((resolve, reject) => {
    const request = indexedDBImpl.open("hodlxxi-social-enrollment-v2-public-approval", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("approval");
    request.onerror = request.onblocked = () => reject(new Error("public approval storage unavailable"));
    request.onsuccess = () => {
      const db = request.result;
      let tx, result;
      try {
        tx = db.transaction("approval", "readwrite", { durability: "strict" });
        if (tx.durability !== "strict") { tx.abort(); fail(); }
        const store = tx.objectStore("approval"), get = store.get(id);
        get.onsuccess = () => { try { result = transform(get.result, store); } catch { tx.abort(); } };
        tx.oncomplete = () => { db.close(); resolve(result); };
        tx.onabort = tx.onerror = () => { db.close(); reject(new Error("public approval storage unavailable")); };
      } catch { db.close(); reject(new Error("public approval storage unavailable")); }
    };
  });
  return Object.freeze({
    claim: (id, authorizationWire) => access(id, (old, store) => {
      if (old !== undefined) { if (old.authorizationWire !== authorizationWire) fail(); return { ...old, owned: false }; }
      const value = { authorizationWire, state: "claimed", approvalWire: null }; store.add(value, id);
      return { ...value, owned: true };
    }),
    save: (id, authorizationWire, approvalWire) => access(id, (old, store) => {
      if (!old || old.authorizationWire !== authorizationWire ||
          old.state !== "claimed" && old.state !== "signed" || old.approvalWire !== null && old.approvalWire !== approvalWire) fail();
      const value = { authorizationWire, state: "signed", approvalWire }; store.put(value, id); return value;
    }),
    read: (id, authorizationWire) => access(id, (old) => {
      if (old !== undefined && old.authorizationWire !== authorizationWire) fail(); return old;
    }),
  });
}

export function createDesktopEnrollmentController({ api, subject, resolveProvider,
  approvalStore = createDesktopApprovalStore(), cryptoImpl = globalThis.crypto, now = Date.now } = {}) {
  let pairing, snapshot, busy = false, cancelled = false;
  const check = () => { if (cancelled || !/^[0-9a-f]{64}$/.test(subject)) fail(); };
  const run = async (work) => { check(); if (busy) fail(); busy = true; try { return await work(); } finally { busy = false; } };
  const inspect = async () => {
    if (!pairing) fail();
    const result = await api.call("inspect", { pairingId: pairing.offer.pairingId }); check();
    if (result.authorizationWire !== null) {
      const envelope = await validateAuthorizationTimeV2(result.authorizationWire, now(), { subject, cryptoImpl });
      if (envelope.context.pairingId !== pairing.offer.pairingId || result.revision !== pairing.offer.revision ||
          result.comparisonCode !== preEnrollmentComparisonCode(await authorizationDigestV2(result.authorizationWire, { subject, cryptoImpl }))) fail();
    }
    snapshot = result; return result;
  };
  return Object.freeze({
    create: () => run(async () => {
      await api.call("context", { role: "desktop" }); check();
      pairing = await api.call("create", {}); check();
      if (pairing.offer.subject !== subject || parsePairingQr(pairing.qr).pairingId !== pairing.offer.pairingId) fail();
      return pairing;
    }),
    inspect: () => run(inspect),
    approve: (comparisonCode) => run(async () => {
      await inspect();
      if (!snapshot?.authorizationWire || comparisonCode !== snapshot.comparisonCode) fail();
      const wire = snapshot.authorizationWire, id = pairing.offer.pairingId;
      const options = { subject, cryptoImpl };
      const valid = async () => { check(); await validateAuthorizationTimeV2(wire, now(), options); check(); };
      await valid();
      let stored = await approvalStore.read(id, wire); await valid();
      if (stored?.state !== "signed") {
        // A prior unfinished claim is ambiguous and must never reacquire a signer.
        if (stored !== undefined) fail();
        stored = await approvalStore.claim(id, wire); await valid();
        if (stored.owned !== true || stored.state !== "claimed" || stored.approvalWire !== null) fail();
        const unsigned = await approvalUnsignedEventV2(wire, options); await valid();
        let provider, signed;
        try {
          provider = await resolveProvider(); await valid();
          if (typeof provider?.getPublicKey !== "function" || typeof provider.signEvent !== "function" ||
              await provider.getPublicKey() !== subject) fail();
          await valid();
          signed = await provider.signEvent(unsigned);
          provider = undefined;
          // Persist returned public evidence even if cancellation overtook the prompt.
          const approvalWire = await createApprovalEventV2(wire, signed?.sig, options);
          if (canonical(signed) !== approvalWire) fail();
          stored = await approvalStore.save(id, wire, approvalWire);
        } finally { provider = undefined; signed = undefined; }
      }
      await valid();
      const accepted = await api.call("approve", { pairingId: id, approvalWire: stored.approvalWire, comparisonCode }); check();
      if (accepted.acceptanceId !== await acceptanceIdV2(stored.approvalWire, options)) fail();
      return accepted;
    }),
    async cancel() { if (!pairing) fail(); cancelled = true; return api.call("cancel", { pairingId: pairing.offer.pairingId }); },
  });
}

export function createPhoneEnrollmentController({ api, store = createMessagingDeviceStore(),
  indexedDBImpl = globalThis.indexedDB, cryptoImpl = globalThis.crypto, CryptoKeyImpl = globalThis.CryptoKey, now = Date.now } = {}) {
  let pending, busy = false, stopped = false;
  const check = () => { if (stopped) fail(); };
  const run = async (work) => { check(); if (busy) fail(); busy = true; try { return await work(); } finally { busy = false; } };
  const random = () => hex(cryptoImpl.getRandomValues(new Uint8Array(32)));
  return Object.freeze({
    scan: (qr) => run(async () => {
      await api.call("context", { role: "phone" }); check();
      if (pending && pending.qr !== qr) fail();
      if (!pending) {
        const offer = await api.call("offer", { qr }); check();
        const parsedQr = parsePairingQr(qr);
        if (offer.pairingId !== parsedQr.pairingId) fail();
        pending = { qr, offer, secret: parsedQr.secret, verifier: random(), deliveryKey: random() };
        if ([pending.secret, pending.verifier].includes(pending.deliveryKey) || pending.verifier === pending.secret) fail();
        pending.key = createMessagingDeviceEd25519KeyV2({ indexedDBImpl, cryptoImpl, CryptoKeyImpl, now,
          getContext: () => ({ subjectHint: pending.offer.subject, revision: pending.offer.revision }) });
      }
      const p = pending;
      if (!p.authorizationWire) {
        let record = await store.read(); check();
        if (record && !p.keyIdentity) fail();
        if (!record) {
          if (p.keyIdentity) fail();
          await preparePhoneMessagingDevice({ enabled: true, subject: p.offer.subject, cryptoImpl, CryptoKeyImpl,
            contextStillCurrent: () => !stopped, store: { read: () => store.read(), create: (value) => {
              p.keyIdentity = Object.fromEntries(["subject", "deviceId", "publicKey", "requestId", "pendingProposal"].map((name) => [name, value[name]]));
              return store.create(value);
            } } });
          record = await store.read(); check();
        }
        if (!record || Object.entries(p.keyIdentity).some(([name, value]) => record[name] !== value)) fail();
        const proposal = parseClosedJson(record.pendingProposal);
        if (!p.content) {
          const issuedAt = iso(now());
          p.content = canonical({ domain: "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1", authorization: {
            schema: "hodlxxi.social_messaging_device_binding_authorization.v1", version: 1,
            bindingRecordSchema: "hodlxxi.social_messaging_device_binding_record.v1", bindingRecordVersion: 1,
            algorithm: "x25519-v1", bindingVersion: 1, subject: record.subject, deviceId: record.deviceId,
            publicKey: record.publicKey, operation: "register", priorBindingId: null, requestId: record.requestId,
            issuedAt, expiresAt: p.offer.expiresAt, bindingValidFrom: issuedAt,
            bindingExpiresAt: iso(now() + p.offer.bindingLifetimeSeconds * 1000) } });
        }
        const prepared = await p.key.prepare(p.content); check();
        const pre = await createBoundPreEnrollmentV2({ content: p.content, ed25519PublicKey: prepared.ed25519PublicKey,
          expiresAt: Date.parse(p.offer.expiresAt), pairingId: p.offer.pairingId },
          { subject: record.subject, proposal, cryptoImpl }); check();
        const context = Object.fromEntries(["pairingId", "secretCommitment", "desktopContext", "createdAt", "expiresAt"].map((name) => [name, p.offer[name]]));
        context.exchangeCommitment = await phoneExchangeCommitmentV2(p.verifier, cryptoImpl); check();
        p.authorizationWire = await createAuthorizationEnvelopeV2({ content: p.content, contextWire: canonical(context), preEnrollmentWire: pre },
          { subject: record.subject, proposal, cryptoImpl }); check();
        const digest = await authorizationDigestV2(p.authorizationWire, { subject: record.subject, cryptoImpl });
        p.possessionProof = await pairingPossessionProofV2(p.secret, digest, cryptoImpl); check();
      }
      return await api.call("propose", { qr: p.qr, authorizationWire: p.authorizationWire, possessionProof: p.possessionProof });
    }),
    status: () => run(async () => { if (!pending) fail(); return api.call("status", { pairingId: pending.offer.pairingId }); }),
    complete: (recover = false) => run(async () => {
      if (!pending?.authorizationWire) fail();
      const p = pending;
      const presentation = await api.call(recover ? "recover" : "issue", { pairingId: p.offer.pairingId,
        secret: p.secret, possessionProof: p.possessionProof, verifier: p.verifier, deliveryKey: p.deliveryKey }); check();
      if (presentation.authenticated !== true || presentation.subject !== p.offer.subject) fail();
      if (!p.challenge) { p.challenge = await api.call("challenge", {}); check(); }
      if (!p.proof) { p.proof = await p.key.createEnrollmentProofV2(p.challenge.enrollmentWire); check(); }
      let result;
      try { result = await api.call("complete", { phoneProofWire: p.proof }); }
      catch { return { outcome: "unknown", messaging: "not-ready", finalAdmission: "denied" }; }
      check();
      if (result.outcome === "unknown" && result.messaging === "not-ready" && result.finalAdmission === "denied") return result;
      if (result.registered !== true || result.messaging !== "not-ready" || result.finalAdmission !== "denied") fail();
      return result;
    }),
    async logout() { stopped = true; return api.call("logout", {}); },
  });
}
