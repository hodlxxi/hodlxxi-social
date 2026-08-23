# Full Recipient Directory V1.22

V1.22 implements only a deterministic Social-side validation boundary for a future authoritative Full recipient directory. It does not acquire a live directory or perform encryption.

## Exact snapshot contract

`src/full-recipient-directory.mjs` accepts one plain data shape with exactly `schema`, `version`, `source`, `snapshotId`, `complete`, `issuedAt`, `expiresAt`, and `recipients`. The schema is `hodlxxi.full_recipient_directory.v1`, version is `1`, source is `hodlxxi-crt`, and `complete` must be `true`. Accessors, inherited properties, symbols, missing or extra fields, partial results, and unsupported versions or sources are unavailable.

`snapshotId` is a bounded opaque identifier. `issuedAt` and `expiresAt` are finite millisecond timestamps. A snapshot must already be issued, remain unexpired, have increasing timestamps, and span no more than five minutes. Recipient count cannot exceed the existing protected-content maximum of 4096. An empty complete snapshot is an available empty directory; unavailable evidence is instead the single immutable `{ state: "unavailable" }` result.

Each recipient has exactly `snapshotId`, `subject`, `encryptionKey`, and `authority`. The recipient snapshot identifier must equal the containing snapshot. Subjects are canonical lowercase 64-hex public keys and must arrive in strictly increasing order. Duplicate subjects and duplicate complete encryption bindings are rejected rather than repaired or silently reordered.

The encryption binding has exactly `algorithm`, `version`, `publicKey`, `validFrom`, `expiresAt`, and `revoked`. V1 supports only `x25519-v1`, a positive safe-integer version, a separate canonical 64-hex public key that differs from the subject, has the unused high bit clear, and is not a prohibited low-order X25519 encoding, a currently valid interval contained by the snapshot interval, and `revoked: false`. Rejecting the high-bit aliases prevents X25519 decoding from masking a non-canonical value into a prohibited coordinate. A subject authentication or Nostr signing key is never implicitly an encryption key. Rotation is represented by a new explicit binding version; old, expired, future, revoked, duplicated, non-capable or unsupported bindings are unavailable.

The embedded authority record has exactly `source`, `version`, `snapshotId`, `subject`, `status`, and `expiresAt`. It must be a version-1 `hodlxxi-crt` current `full` assertion for the exact recipient and snapshot and may not outlive the snapshot. Limited, Operator, Nostr, synthetic, friendship, sponsor, malformed, mismatched, unknown and unavailable claims cannot enter an accepted directory.

## Disclosure and lifecycle boundary

Every validation or resolver failure returns the same immutable unavailable result. The boundary logs nothing and provides no error detail, count, lookup, search, notification, membership probe or synthetic fallback. The available result exists only for injection into future protected-content machinery; no production selector or route consumes it.

A newly complete snapshot can exclude a removed member, and revoked or expired bindings prevent their future selection. Removal cannot retroactively erase plaintext that a formerly authorized recipient already observed. Cryptographic forward secrecy, re-encryption and deletion guarantees are not provided by this validator.

## Not implemented

There is no live directory, endpoint, polling, database, durable storage, protected transport, encryption or decryption implementation, key generation, private-key access, key custody, signing, browser selector, product route, relay audience tag, client filtering, CSS access control, plaintext protected event, deployment or production availability. HODLXXI runtime/CRT remains an external read-only authority; Social never grants Full or Operator.
