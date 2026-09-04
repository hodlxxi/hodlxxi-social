# Social V1.28 Secure Messaging Architecture

## Status

V1.28 is a staged design and implementation workstream built on top of the
V1.27 opaque recipient capability boundary.

This document defines the security and product contract before live crypto,
transport, storage, or production wiring is added.

The first V1.28 implementation phase is UI-only. It must not create real
recipient capabilities, encryption keys, ciphertext, messages, database rows,
relay traffic, or production behavior.

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
- `ready` — this device has a current local private key with a current public
  binding;
- `rotating` — a replacement binding is being established;
- `revoked` — the previous device binding is no longer eligible;
- `unavailable` — state cannot be safely established.

Unknown or malformed state fails closed to `unavailable`.

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

The first V1.28 frontend shell is intentionally inert.

It may include preview states for:

- secure messaging ready;
- secure messaging not configured;
- no conversations;
- sample Full recipient picker;
- sample encrypted conversation presentation;
- device list;
- desktop and mobile layouts.

It must perform no:

- `fetch`;
- WebSocket connection;
- recipient-capability request;
- crypto operation;
- key generation;
- localStorage/sessionStorage/IndexedDB write;
- server persistence;
- Nostr operation;
- production route wiring.

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

No V1.28 phase is a production activation by itself.

V1.27 must complete its outstanding live positive-path gate before V1.28 live
recipient crypto wiring can rely on `rc_...` in production.
