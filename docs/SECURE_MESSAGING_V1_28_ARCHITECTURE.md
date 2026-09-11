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

## V1.28E browser encryption implementation

V1.28E selects exact-pinned `@hpke/core` 1.9.0 and RFC 9180 Base mode for
recipient content-key wrapping. The suite is DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-128-GCM. The message body is UTF-8 text, capped at 16,384
bytes, and encrypted exactly once with a fresh random 256-bit content key and
a fresh random 96-bit nonce using native WebCrypto AES-256-GCM. One independent
one-shot HPKE operation wraps that same key for each current recipient device.
V1.28E does not use or export the sender's persisted Social device private key.

The frozen returned schema is `hodlxxi.social_message_envelope.v1`, version 1.
It contains ciphertext, HPKE encapsulations, the recipient-package snapshot
identifier, and sorted opaque device handles only. It has no recipient alias,
recipient capability, raw recipient public key, canonical subject, protected
plaintext, plaintext content key, private key, or timestamp. The exact
envelope, authenticated-header, HPKE domain-separation, dependency provenance,
browser-delivery, replay rule, and security non-claims are defined in
[`SECURE_MESSAGING_V1_28E_CRYPTO_ENVELOPE_V1.md`](./SECURE_MESSAGING_V1_28E_CRYPTO_ENVELOPE_V1.md).

This phase is still messaging-inert outside the local module: the authenticated
entry graph does not import it, the composer and Send remain disabled, and no
ciphertext submission, message route, inbox, database, delivery, WebSocket,
decryption UI, conversation persistence, or sender-history synchronization is
implemented.

## V1.28F.1 exact server envelope boundary

V1.28F.1 adds the first, deliberately small part of the future V1.28F server
boundary. `src/server/message-envelope-v128f1.mjs` accepts only the exact
V1.28E `hodlxxi.social_message_envelope.v1`, produces a fresh deeply frozen
ciphertext-only object, emits one explicit no-whitespace ASCII JSON wire form,
requires raw wire input to round-trip byte for byte within 32,768 bytes, and
computes a V1 domain-separated SHA-256 digest. The digest representation is
distinct from a recipient-package snapshot identifier.

This is not V1.28F completion. The module is not composed into the server or
browser and adds no HTTP route, store, filesystem use, PostgreSQL dependency,
environment, inbox, submission, delivery, or decryption behavior. Recipient
routing is unresolved, and device-handle equivalence and stability across a
future routing/storage boundary are not proven. Executable authorization,
routing, storage, and inbox ports are therefore deferred rather than freezing
speculative UBID semantics. See
[`SECURE_MESSAGING_V1_28F1_ENVELOPE_STORAGE_BOUNDARY.md`](./SECURE_MESSAGING_V1_28F1_ENVELOPE_STORAGE_BOUNDARY.md).

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
`requestId`, `state`, `acceptedBinding`, `authorization`,
`pendingAuthorization`, `pendingProposal`, and `rotation`. The schema is
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

## Identity-authorized device-binding successor

The Social source now also contains a dedicated, disabled-by-default successor
to the OAuth-only binding mutation. It is enabled only by the complete
`messagingDeviceAuthorization` server configuration. The existing read-only
binding snapshot remains unchanged. When the successor is enabled, the legacy
Social and UBID device-binding POST paths are fail-closed; when it is disabled,
the pre-existing OAuth/session behavior is unchanged.

For register, rotate, revoke, or eligible legacy adoption, the browser sends
only UBID's closed canonical proposal to the same-origin Social BFF. Social
uses its existing confidential-service assertion machinery and the canonical
viewer bearer held in the opaque server session to obtain one authoritative
UBID intent. The BFF returns the closed intent document required for the
explicit signing action: the derived claim and semantic digest, expected
participant public key, exact unsigned kind-27236 event, signature format, and
separate short-lived intent token. The proposal cannot supply a subject,
binding version, binding interval, predecessor, derived binding ID, request
clock, Current-Full proof, event ID, or event fields.

Before either signer adapter is read, the browser compares the parsed semantic
claim with the canonical proposal that initiated the action. Register binds
the operation, request ID, device ID, proposed public key, null predecessor,
and binding version 1. Rotate binds the operation, request ID, device ID,
replacement public key, and exact predecessor binding ID. Revoke binds the
operation, request ID, device ID, and exact predecessor. Adoption binds its
action, new request ID, and selected existing binding ID. Cross-operation or
field substitution fails before NIP-07 resolution or NIP-46 transport.

The explicit browser action obtains the NIP-07 provider only for that action,
calls `getPublicKey()`, and requires exact equality with the authenticated
lowercase x-only session subject before reading or calling `signEvent`. It asks
for exactly one signature over the returned event. The browser then requires
the result to preserve the exact pubkey, kind, whole-second `created_at`,
content, tag values, and tag order; recomputes the NIP-01 event ID; and verifies
the BIP340 signature through the existing canonical browser verifier. The
provider is released after the action. The event is not published and no relay
operation exists in this path.

`web/nip46-messaging-device-signer-v1.mjs` is a narrow injectable, single-use
`sign_event` adapter with an exact configured subject, timeout, and cancellation
boundary. It has no configured transport, relay URL, account, secret, polling,
retry, discovery, publication, or automatic fallback. The same intent and
signed-event validator is applied after either signer. Consequently this source
contains the NIP-46 adapter seam but does not claim a live NIP-46 runtime.

The browser submits only the closed signed event plus the intent token in
`X-HODLXXI-Device-Binding-Intent`. Social revalidates the event ID, signature,
subject, carrier fields, semantic content/digest, request ID, action, and token
correspondence. It reconstructs UBID's existing canonical flattened signed
payload and sends the intent token separately on the authoritative internal
authorization route. UBID remains authoritative for the token signature,
trusted clock, final Current-Full and lifecycle state, binding ID, replay, and
atomic mutation. Exact accepted retries preserve the same canonical result;
conflicts and malformed or expired intent/event results return only the generic
unavailable response.

Before requesting an intent or signer, the browser durably stores the exact
canonical proposal and any dedicated rotation replacement key. After local
event-ID and BIP340 verification, the browser durably stores the
canonical signed public event, its exact canonical proposal, and the separate
intent token in the existing device-local IndexedDB record before submission.
No participant private key or serialized X25519 private key is present in this
retry material. On re-entry, the controller first reads a fresh authoritative
binding snapshot. A snapshot that proves register or rotate is active, or that
the revoked predecessor is absent, completes the pending operation without a
new signature. Otherwise startup exposes an explicit continue action and does
not submit or sign. After that action reconciles authoritative state again, a
still-valid pending operation resubmits the exact same event and token; an
expired operation obtains replacement intent/signature material for the same
persisted proposal. Tampered material fails closed. Pending material is cleared
only following canonical success. IndexedDB updates compare the caller's exact
public record revision inside the read-write transaction, reject stale rotation
or retry replacement/clearing, and always promote the private CryptoKey from the
winning stored rotation rather than from caller-supplied state.

The enabled controller exposes four explicit product actions. Registration
keeps generate, strict IndexedDB commit, read-back, then intent ordering and is
not ready until its authorization proof and exact accepted binding reconcile.
An old local record without an authorization marker remains schema-compatible
but renders authorization-required even when its OAuth-only binding is active;
explicit adoption uses a new request ID and leaves its binding row and X25519
key unchanged. Rotation first persists a replacement non-extractable key while
retaining its predecessor key and binding metadata, and promotes it only after
canonical acceptance plus snapshot reconciliation. Revocation retains local
key state until the same confirmation and then renders revoked, never ready or
routable. Startup reconciliation is read-only with respect to signing: it may
finalize already accepted signed material but never resubmits, opens NIP-07, or
invokes NIP-46.

The confidential-service private key remains server-only. Participant Nostr
private keys and Social X25519 private keys are never sent to Social or UBID.
The persisted non-extractable X25519 `CryptoKey` exception remains unchanged
and is not used for identity signing. Kind 27236 is a deterministic private
carrier only and is never published to relays.

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
- V1.28F.1 — inert exact server envelope/wire/digest boundary;
- V1.28F — later ciphertext-only inbox/transport/storage completion;
- V1.28G — browser-local decryption and multi-device rehearsal.

Each phase receives its own tests and review gate.

## Production rule

No V1.28 source phase is a live messaging activation by itself. The V1.28B
browser assets may be deployed while messaging remains inert.

Before later recipient crypto wiring relies on `rc_...` for a live message
path, the authenticated production positive path must be explicitly verified
for the then-current V1.27 deployment. Route existence or an unauthenticated
fail-closed response alone is not that positive-path proof.
