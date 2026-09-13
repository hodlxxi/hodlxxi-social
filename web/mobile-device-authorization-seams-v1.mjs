// Explicit, injectable contract seams. Not imported by the application entry.
import {
  canonicalMessagingDeviceAuthorizationProposal,
  canonicalMessagingDeviceJson as canonical,
  createNip07MessagingDeviceSigner,
  MESSAGING_DEVICE_SIGNATURE_FORMAT
} from "./messaging-device-authorization-v1.mjs";
import { createMessagingDeviceStore } from "./messaging-device-v128c1.mjs";
import {
  METHODS, mobileUnsignedEvent, parseMobileAuthorization,
  pairingComparisonCode, verifyMobileEvent
} from "./mobile-device-authorization-contract-v1.mjs";

const deny = () => { throw new TypeError("mobile device authorization unavailable"); };
const hex = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const toHex = (v) => [...v].map((b) => b.toString(16).padStart(2, "0")).join("");

// A claimed subject is only a local public-key hint before LEGACY verification.
// No login or device authority follows from allocating this pending record.
export async function preparePhoneMessagingDevice({
  enabled = false, subject, store = createMessagingDeviceStore(),
  cryptoImpl = globalThis.crypto, CryptoKeyImpl = globalThis.CryptoKey,
  contextStillCurrent = () => true
} = {}) {
  if (enabled !== true || !hex(subject)) deny();
  const check = () => { if (contextStillCurrent() !== true) deny(); };
  check();
  if (await store.read() !== undefined) deny();
  check();
  const pair = await cryptoImpl.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  check();
  const privateKey = pair.privateKey;
  if (!(privateKey instanceof CryptoKeyImpl) || privateKey.type !== "private" || privateKey.extractable !== false ||
      privateKey.algorithm.name !== "X25519" || canonical(privateKey.usages) !== '["deriveBits"]' ||
      !(pair.publicKey instanceof CryptoKeyImpl) || pair.publicKey.type !== "public" ||
      pair.publicKey.algorithm.name !== "X25519" || pair.publicKey.extractable !== true || pair.publicKey.usages.length) deny();
  const raw = await cryptoImpl.subtle.exportKey("raw", pair.publicKey);
  check();
  if (raw.byteLength !== 32) deny();
  const publicKey = toHex(new Uint8Array(raw));
  const randomId = () => toHex(cryptoImpl.getRandomValues(new Uint8Array(32)));
  const deviceId = randomId(), requestId = randomId();
  if (deviceId === requestId || publicKey === subject) deny();
  const proposal = { deviceId, expectedBindingId: null, operation: "register", publicKey, requestId };
  const pendingProposal = canonicalMessagingDeviceAuthorizationProposal(proposal);
  // The existing store performs an atomic add and strict IndexedDB commit.
  await store.create({ schema: "hodlxxi.social_messaging_device_local.v1", version: 1,
    subject, deviceId, privateKey, publicKey, requestId, state: "pending-register",
    acceptedBinding: null, authorization: null, pendingAuthorization: null, rotation: null, pendingProposal });
  check();
  const saved = await store.read();
  check();
  if (!saved || saved.subject !== subject || saved.deviceId !== deviceId || saved.publicKey !== publicKey ||
      saved.requestId !== requestId || saved.pendingProposal !== pendingProposal ||
      !(saved.privateKey instanceof CryptoKeyImpl) || saved.privateKey.extractable !== false ||
      saved.privateKey.type !== "private" || saved.privateKey.algorithm.name !== "X25519" ||
      canonical(saved.privateKey.usages) !== '["deriveBits"]') deny();
  return Object.freeze(proposal);
}

export function createDesktopPhoneApproval({
  enabled = false, getContext, claimApproval, persistRetry, resolveProvider,
  now = () => Math.floor(Date.now() / 1000), cryptoImpl = globalThis.crypto
} = {}) {
  let used = false, cancelled = false;
  return Object.freeze({
    cancel() { cancelled = true; },
    async approve({ authorization, comparisonCode, proposal } = {}) {
      if (enabled !== true || used || cancelled || typeof getContext !== "function" ||
          typeof claimApproval !== "function" || typeof persistRetry !== "function" ||
          typeof resolveProvider !== "function") deny();
      used = true;
      const initial = { ...getContext() };
      if (!initial || !hex(initial.subject) || !hex(initial.revision)) deny();
      const subject = initial.subject, revision = initial.revision;
      const check = () => {
        const context = getContext();
        if (cancelled || context?.subject !== subject || context?.revision !== revision ||
            context?.pairingId !== initial.pairingId || context?.transcriptDigest !== initial.transcriptDigest) deny();
      };
      const options = { subject, proposal, expectedMethod: METHODS.qr, now: now(), cryptoImpl };
      const parsed = await parseMobileAuthorization(authorization, options);
      check();
      if (parsed.context.pairingId !== initial.pairingId || parsed.digest !== initial.transcriptDigest ||
          comparisonCode !== pairingComparisonCode(parsed.digest)) deny();
      const expected = await mobileUnsignedEvent(authorization, options);
      check();
      // Must be an atomic compare-and-swap in the caller's shared public state.
      if (await claimApproval({ revision, pairingId: initial.pairingId, transcriptDigest: parsed.digest }) !== true) deny();
      check();
      const signer = createNip07MessagingDeviceSigner({ resolveProvider: () => {
        check();
        let provider = resolveProvider();
        if (!provider || Object.getPrototypeOf(provider) !== Object.prototype) deny();
        const getPublicKey = Object.getOwnPropertyDescriptor(provider, "getPublicKey")?.value;
        if (typeof getPublicKey !== "function") deny();
        // Recheck across the wallet prompt before reading signEvent.
        return {
          async getPublicKey() {
            const key = await getPublicKey.call(provider);
            check();
            if (key !== subject) { provider = undefined; deny(); }
            return key;
          },
          async signEvent(event) {
            check();
            if (now() >= parsed.semantic.expiresAt) { provider = undefined; deny(); }
            const signEvent = Object.getOwnPropertyDescriptor(provider, "signEvent")?.value;
            if (typeof signEvent !== "function") { provider = undefined; deny(); }
            try { return await signEvent.call(provider, event); }
            finally { provider = undefined; }
          }
        };
      } });
      const event = await signer.signEventForSubject({ subject, unsignedEvent: expected.unsignedEvent });
      check();
      const verified = await verifyMobileEvent(authorization, event, { ...options, now: now() });
      check();
      const retry = canonical({ authorization, signedEvent: verified, signatureFormat: MESSAGING_DEVICE_SIGNATURE_FORMAT });
      // A later submit/reconcile phase consumes this exact public retry. It may
      // never regenerate an event after an ambiguous outcome.
      await persistRetry(retry, { revision, transcriptDigest: parsed.digest });
      check();
      return retry;
    }
  });
}
