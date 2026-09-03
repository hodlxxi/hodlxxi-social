# Opaque Recipient Capability V1

## Status

V1.27 Phase A is source-only.

It defines a bounded process-local capability contract for selecting one
viewer-private Full Directory alias for a future direct-message action.

It adds no HTTP route, production composition, deployment, UI, raw recipient
resolution, message transport, encryption, decryption, X25519 use, Nostr use,
database write, durable persistence, or browser persistence.

## Trusted caller boundary

The capability store does not determine Full membership and does not obtain a
Full Directory itself.

The future server-side caller must already possess:

1. the exact authenticated canonical viewer subject;
2. the exact current opaque Social server-session identifier; and
3. one freshly accepted privacy-safe Full Directory for that exact viewer.

The session identifier must come from the already authenticated server-side
Social session. A capability issued in one login session must not become usable
from a later login session for the same subject.

`currentAliases` must be derived server-side from that accepted directory. It
must never be accepted from a browser request as an authority claim.

`now` exists as an explicit input for deterministic testing and composition. A
future production caller must supply it from a trusted server clock. Browser
time must never determine capability validity.

Issuance accepts a selected alias only when that exact alias occurs in the
current accepted directory.

Resolution again requires the current accepted alias set. If the target leaves
the current Full population, or the privacy alias namespace rotates so that the
old alias disappears, the existing capability becomes unavailable.

The capability therefore does not extend Full Directory freshness or
membership authority.

## Capability semantics

A capability is a fresh 256-bit random opaque bearer value with the textual
prefix `rc_`.

The issuance result contains only:

- `state`;
- `capability`;
- `expiresAt`.

It does not contain the viewer subject, selected alias, target subject, covenant
key, X25519 key, Nostr key, XPUB, graph position, sponsor relation, or other
participant metadata.

The process-local record is bound to:

- the authenticated viewer subject;
- the exact authenticated Social session;
- the selected viewer-private alias;
- the exact purpose `direct-message`;
- a short expiry time.

The default lifetime is 60 seconds. Configuration longer than five minutes is
rejected.

## Fail-closed behavior

Unknown, malformed, expired, cross-viewer, wrong-purpose,
capacity-exhausted, non-current-alias, duplicate-alias, unsafe-alias, and
random-collision cases produce the same immutable:

```json
{"state":"unavailable"}
```

No target lookup result, population count, or membership explanation is
returned.

## Storage boundary

Phase A storage is process-local memory only.

There is:

- no database table;
- no filesystem storage;
- no localStorage;
- no sessionStorage;
- no IndexedDB;
- no cache shared across processes.

A Social process restart destroys all outstanding capabilities.

A capability from an ended login session cannot be used by a later session for
the same subject because successful resolution requires the exact original
session binding. Old in-memory records may remain until their short TTL expires,
but they no longer become usable merely because the same subject logs in again.

A future horizontally scaled deployment must not assume this process-local
store works across independent instances without a separately reviewed shared
or cryptographically self-contained capability design.

## Non-authority

A recipient capability is not:

- identity;
- Full proof;
- authentication;
- friendship;
- sponsorship;
- covenant evidence;
- an encryption key;
- a Nostr key;
- permission to spend;
- permission to send a message by itself.

A later message action must independently re-check the authenticated viewer,
current authority, current recipient eligibility, capability purpose, and
current recipient cryptographic readiness.

## V1.27 / V1.28 boundary

V1.27 selects an opaque recipient only.

It must not resolve that participant to a raw browser-visible subject and must
not expose an X25519 public key.

Recipient cryptographic readiness and client-side encrypted direct messaging
remain separate V1.28 work.
