# Social V1.28 Secure Messaging Architecture

## Status

V1.28 is a staged design and implementation workstream built on top of the
V1.27 opaque recipient capability boundary.

This document defines the security and product contract before live crypto,
transport, storage, or production wiring is added.

The first V1.28 implementation phase is messaging-inert. V1.28B may use the
already existing authenticated read-only Social session and Full Directory
requests needed to render real current Full recipients, but it must not create
real recipient capabilities, encryption keys, ciphertext, messages, database
rows, messaging relay traffic, or live message-delivery behavior.

## V1.27 dependency

V1.27 answers only:

> Which current Full-network card did this authenticated viewer select?

The browser supplies one viewer-private alias and receives a short-lived opaque
`rc_...` capability. That capability is session-bound, subject-bound,
purpose-bound, short-lived, and does not expose the selected participant's raw
identity.

V1.28 starts after that capability exists.

V1.28 must never turn `rc_...` into a raw browser-visible canonical subject,
Bitcoin key, Nostr key, covenant key, XPUB, sponsor relation, graph position,
or other identity record.

## Core security invariant

For internal HODLXXI direct messages:

`sender device -> local encryption -> HODLXXI ciphertext storage -> recipient device -> local decryption`

The server may authenticate, authorize, route, retain, and return encrypted
objects. It must not receive protected plaintext and must not hold participant
private encryption keys.

## Separate key roles

The following roles remain distinct:

- Bitcoin covenant or spending keys;
- Checking XPUB material;
- UBID authentication/signing identity;
- optional external Nostr signing identity;
- Social device encryption keys.

A Social encryption key must not be derived from, reused as, or equated with a
Bitcoin key, XPUB, OAuth secret, server signing key, Nostr identity key, or
recipient capability.

## Device encryption identity

Secure messaging is device-based.

One authenticated HODLXXI subject may register multiple independently
revocable encryption-device bindings, for example:

- MacBook;
- iPhone;
- iPad.

Each device owns one private encryption key locally. The server stores only a
versioned public-key binding and non-secret lifecycle metadata needed for
routing, rotation, and revocation.

The private encryption key must not be uploaded to HODLXXI.

A device key is not membership authority. Registering, rotating, or revoking a
device key must not change Limited/Full status, sponsorship, covenant evidence,
or trust.

## Recipient crypto package

The ordinary Full Directory remains alias-only.

A recipient crypto package may be obtained only after all of the following are
true:

1. the caller has an authenticated Social session;
2. the current authority projection is Full;
3. the selected viewer-private alias is still present in a fresh accepted Full
   Directory;
4. the caller presents a valid V1.27 `direct-message` recipient capability;
5. the recipient has at least one current, non-revoked messaging-device public
   binding.

The package must be short-lived and purpose-bound.

The package may contain only the minimum cryptographic routing material needed
for local encryption, such as:

- opaque device key handle;
- encryption algorithm/version;
- public encryption key;
- validity window.

It must not include raw canonical recipient identity, Bitcoin keys, Nostr keys,
XPUBs, names, labels, graph relationships, or population metadata.

A recipient encryption public key is not secret, but it is a correlatable
identifier and therefore must not be exposed through the general Full
Directory or ordinary profile surfaces.

## Multi-device message model

For each message the sender device generates one fresh random content key
`K_message`.

The plaintext body is encrypted once with `K_message`.

`K_message` is then wrapped independently for every currently authorized target
device. The sender's own active devices may also receive wrapped copies so the
sender can read Sent history from another device.

Conceptually:

```text
plaintext
   |
   | encrypt once with K_message
   v
ciphertext

K_message
   |-- wrapped for recipient device A
   |-- wrapped for recipient device B
   |-- wrapped for sender device A
   `-- wrapped for sender device B
```

The server stores ciphertext plus wrapped content-key records. It never stores
`K_message` in plaintext.

## Cryptographic primitive policy

V1.28 UI work does not select or implement a new cryptographic construction.

The repository already models separate versioned X25519 recipient-key bindings.
The live encryption phase must use a separately reviewed, standard construction
and must not hand-roll an ad-hoc X25519 + KDF + AEAD protocol.

Before live crypto wiring, the implementation must document and test:

- primitive provenance;
- algorithm identifiers and versioning;
- nonce requirements;
- authenticated associated data;
- key derivation rules;
- malformed-input behavior;
- replay behavior;
- key rotation and revocation behavior;
- browser compatibility;
- deterministic test vectors or authoritative compatibility vectors.

No fallback to an unreviewed crypto path is allowed.

## Mobile requirement

Internal Social messaging must not require a NIP-07 browser extension.

Login and decryption are separate concerns.

A user may authenticate through any accepted UBID login path, including a
mobile-compatible path, and then use that device's own Social encryption key to
open internal messages.

Alby or another NIP-07 signer may remain useful for optional external Nostr
operations, but it must not be a mandatory dependency for internal HODLXXI
message decryption.

## Device setup states

The product exposes an explicit messaging-device state:

- `not-configured` — this browser/device has no accepted local messaging key;
- `pending-register` — a local device key is committed and its public
  registration is being reconciled;
- `ready` — this device has a current local private key with a current public
  binding;
- `rotating` — a replacement binding is being established;
- `revoked` — the previous device binding is no longer eligible;
- `unavailable` — state cannot be safely established.

Unknown or malformed state fails closed to `unavailable`.

## Browser device setup implementation

V1.28C.1 adds explicit **Set up this device** to authenticated Full Messages.
`web/messaging-device-v128c1.mjs` owns this bounded lifecycle; the authenticated
entry passes only device state and busy status to the Messages renderer. The
alias-only recipient directory and viewer-private labels remain separate.

Each browser generates a dedicated X25519 device identity with native WebCrypto:
`generateKey({ name: "X25519" }, false, ["deriveBits"])`. The private CryptoKey
must be non-extractable. The implementation checks both key types, algorithms,
usages and extractability before exporting only the public key as exactly 32
raw bytes, represented by lowercase hex64. This call shape follows the
[WebCrypto X25519 Generate Key steps](https://www.w3.org/TR/webcrypto/#x25519-operations):
the public key is exportable while private extractability follows the `false`
argument. An offline native WebCrypto test verifies these properties and
structured-clone retention. Each browser checks them at runtime; unsupported
X25519, CryptoKey persistence, or strict transaction durability fails closed.
There is no extractable-private-key fallback or crypto dependency.

The dedicated IndexedDB database `hodlxxi-social-messaging-device-v1`, version 1,
has one `device` store and one `current` record. Its closed fields are `schema`,
`version`, `subject`, `deviceId`, `privateKey` (the CryptoKey), `publicKey`,
`requestId`, `state`, and `acceptedBinding`. The schema is
`hodlxxi.social_messaging_device_local.v1`. IndexedDB's native structured clone
retains the non-extractable key; application JSON serialization, private-key
export, localStorage, and sessionStorage are never used for this record. Only
browser memory and this local store receive the private CryptoKey. It is never
uploaded, logged, rendered, or included in a returned UI projection. This is
the sole narrow persistence exception documented in AGENTS.md; participant
signing keys and server-side private-key custody remain prohibited. This key
is independent of Bitcoin, XPUB, UBID, OAuth, Nostr, and recipient capabilities.

Before setup, the controller re-reads `/auth/session`, requires the current
Messages access context to be Full, and reconciles the existing local record
with `/auth/messaging-device-bindings`. A different subject's record is never
adopted or replaced. Session and access checks repeat across asynchronous
boundaries, immediately before POST, and before accepting ready state. Route
exit and logout cancel outstanding work. An in-flight request cannot be
undone, so cancellation preserves its original subject-bound pending record;
it never reassigns that record to a later session. The BFF remains the authority
for the session that actually authenticates the request; the browser supplies
no canonical subject in its registration command.

First setup uses two independent `getRandomValues(new Uint8Array(32))` calls
for `deviceId` and `requestId`. It atomically adds the local record as
`pending-register`, requests IndexedDB `durability: "strict"`, awaits
transaction `oncomplete` (request success is insufficient), and reads back the
retained record before POST. An add cannot overwrite a concurrent tab's
record. Updates preserve the stored private key and reject identity or accepted
metadata changes. Storage failure prevents registration.

The server receives only this public command through the existing same-origin
OAuth/session BFF, using `credentials: "same-origin"`, `cache: "no-store"`,
`redirect: "error"`, and `Content-Type: application/json`:

```json
{
  "schema": "hodlxxi.social_messaging_device_binding_command.v1",
  "version": 1,
  "operation": "register",
  "deviceId": "<64 lowercase hex>",
  "algorithm": "x25519-v1",
  "publicKey": "<64 lowercase hex>",
  "expectedBindingId": null,
  "requestId": "<64 lowercase hex>"
}
```

Transport timeout, lost response, and malformed registration results leave
the durable record pending. Re-entry first reads a fresh, complete, strictly
validated server snapshot. One exact active `deviceId` + `publicKey` binding
can complete pending setup without POST. Otherwise, an unaccepted pending
record retries the identical command with its original requestId and key;
there is no automatic replacement, rotation, or revocation. A valid register
result retains only accepted bindingId, version, and validity metadata; a
subsequent matching snapshot and successful local ready commit are required
before the UI becomes ready. Ready re-entry must match that metadata exactly.
Malformed, duplicate, missing-ready, revoked, expired, or conflicting bindings
fail closed to unavailable without deleting the original record.

The UBID provider contract verified at authority commit
`e4b726f4050d1e1f8b606a9acd9bd2cb618ee1b7` uses integer Unix milliseconds for
snapshot `issuedAt`/`expiresAt` and active-device `validFrom`/`expiresAt`. The browser
uses the same authoritative millisecond unit internally and converts the BFF
registration result's canonical UTC-second strings to integer Unix milliseconds
before persisting accepted metadata. Freshness, expiration, and exact metadata
reconciliation therefore compare one explicit cross-component unit. The
browser does not infer time units from timestamp magnitude.

The four product states are not-configured, pending-register, ready, and
unavailable. Ordinary Messages never renders subject, deviceId, bindingId, or
encryption keys. Ready means device setup is reconciled; the composer remains
disabled and no message encryption, decryption, plaintext submission, inbox,
ciphertext storage, or transport is implemented. This slice does **not** select
the final V1.28E message encryption construction or perform key agreement.

## New-device history rule

A newly registered device is not automatically entitled to historical message
keys.

V1.28 may initially show an honest notice that older messages are unavailable
on a new device.

A later separately reviewed device-linking flow may allow an already authorized
device to re-wrap historical content keys for a newly authorized device without
revealing plaintext or private keys to the server.

## Device revocation

Revoking a device stops future content-key wrapping for that device.

Revocation does not magically erase ciphertext or keys already received by a
previously authorized device. The product must not claim retroactive secrecy it
cannot enforce.

## Server storage boundary

The messaging backend may store only bounded message records required for
routing and ciphertext retrieval.

Permitted classes of storage include:

- opaque message or conversation reference;
- ciphertext;
- wrapped content-key records;
- opaque device-key handles;
- creation/receipt/retention timestamps;
- minimal authorization and delivery metadata.

Forbidden protected storage includes:

- plaintext message body;
- participant private encryption key;
- plaintext content key;
- arbitrary Full Directory snapshot copied into message storage;
- browser private labels;
- Bitcoin private material;
- Nostr private material.

## Metadata minimization

End-to-end encryption protects content, not all metadata.

The server necessarily knows some authenticated and routing facts. V1.28 must
minimize persistent metadata and must prefer opaque conversation, recipient,
and device handles over raw public keys wherever possible.

Ordinary browser message surfaces must not render raw canonical participant
keys or raw encryption keys.

## Full-only first release

The first live V1.28 direct-message release is Full-to-Full only.

This matches the V1.27 Full Directory and recipient-capability authority model
and keeps the initial authorization surface narrow.

Limited-user direct messaging is a separate product and authority decision and
must not be added implicitly by V1.28.

## UI contract

The secure messaging UI may render:

- viewer-private label, if one exists locally;
- viewer-private alias as a fallback presentation identifier;
- Current Full status;
- secure-device readiness state;
- conversation list state;
- unread count;
- message ciphertext-derived delivery/open state once available;
- explicit end-to-end-encryption disclosure.

The UI must not invent real conversations or claim that demo transcript content
was delivered.

Any preview fixture must be unmistakably labeled preview/demo and must not be
wired into the authenticated production entry graph.

## UX target

Desktop layout:

- left conversation rail;
- selected conversation header;
- end-to-end-encryption badge;
- message transcript;
- compose field;
- device-security status;
- New Message action using Full Network members.

Mobile layout:

- conversation list as the primary view;
- single selected conversation view;
- compact encryption status;
- large touch-friendly composer;
- no dependence on browser extensions for internal decryption.

## New Message flow

The target user flow is:

```text
Messages
  -> New message
  -> select a current Full Network card
  -> V1.27 obtains rc_... capability
  -> V1.28 obtains short-lived crypto package
  -> browser encrypts locally
  -> ciphertext submit
```

The user does not paste an `npub`, raw x-only key, Bitcoin key, or encryption
public key into the ordinary Social messaging UI.

## External Nostr boundary

Internal Social direct messages are HODLXXI-controlled ciphertext transport by
default.

They are not automatically published to a Nostr relay.

External Nostr messaging, if added later, is an explicit interoperability mode
with its own privacy, key, relay, and metadata review.

## UI-only Phase B boundary

The first V1.28 frontend shell is intentionally inert with respect to
messaging operations. It may perform the existing read-only same-origin
`GET /auth/session` and, for an authenticated current Full viewer,
`GET /auth/full-directory` calls needed to render the accepted alias-only
recipient presentation.

It may include preview states for:

- secure messaging ready;
- secure messaging not configured;
- no conversations;
- sample Full recipient picker;
- sample encrypted conversation presentation;
- device list;
- desktop and mobile layouts.

It must perform no messaging-side:

- recipient-capability issuance request;
- recipient crypto-package request;
- messaging-device registration request;
- encryption or decryption operation;
- messaging key generation;
- message or capability persistence in localStorage/sessionStorage/IndexedDB;
- ciphertext/message submission;
- messaging WebSocket connection;
- Nostr messaging operation;
- message database/server persistence;
- live messaging transport wiring.

## Subsequent phases

- V1.28A — architecture and threat-boundary contract;
- V1.28B — inert secure-messaging UX shell;
- V1.28C — device-key registration and lifecycle;
- V1.28D — `rc_...` to recipient crypto-package boundary;
- V1.28E — reviewed browser encryption implementation;
- V1.28F — ciphertext-only inbox/transport/storage;
- V1.28G — browser-local decryption and multi-device rehearsal.

Each phase receives its own tests and review gate.

## Production rule

No V1.28 source phase is a live messaging activation by itself. The V1.28B
browser assets may be deployed while messaging remains inert.

Before later recipient crypto wiring relies on `rc_...` for a live message
path, the authenticated production positive path must be explicitly verified
for the then-current V1.27 deployment. Route existence or an unauthenticated
fail-closed response alone is not that positive-path proof.
