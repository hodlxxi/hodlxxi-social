# Staging transport continuation for #73 / UBID #588

This branch remains incomplete and must not be activated. The CLI has no
trusted delivery-provider composition, and the authenticated Messages UI is
not wired to send, retrieve and decrypt messages. No source test establishes
live Alice/Bob browser acceptance.

`POST /auth/messages` accepts the existing exact ciphertext envelope and
recipient capability. Inbox retrieval now uses `POST /auth/messages/inbox`
with the frozen canonical `hodlxxi.social_messaging_recipient_self_request.v1`
body. The old GET plus a device handle returns 405. Both operations require
same-origin submission, the matching Social session, fresh external Full
authority, and canonical V1 Ed25519 device-proof bytes in
`x-hodlxxi-message-device-proof`.

Parsing those proof bytes grants no authority. The trusted UBID provider must
verify its own stored challenge, actual method/path/body, current exact
Enrollment V2 association, session generation, Full evidence and replay state,
then consume and apply the operation transactionally. Both exact proof bytes
and original request bytes reach the mailbox authorizer. The frozen proof
module still denies final device admission. No option or browser field enables
that dormant owner, and no default mailbox authorizer exists.

The mailbox now installs records in a fixed, append-only set of slots with
atomic no-overwrite hard links. Concurrent instances compete for the lowest
free slot and rescan on collisions. This prevents the draft's count-then-write
quota race, preserves exact retries and rejects conflicting message IDs. The
private directory is bounded to 2,048 records and the inbox to 25 messages.
There is no eviction or historical pagination yet. Use a fresh dedicated
candidate mailbox: earlier draft hash-named records have no automatic format
migration and are rejected.

Tests cover missing/malformed device proofs, independent authorization
denials, replay conflicts, concurrency, quota, canonical bytes, and restart
persistence. A separate component integration uses the normal HTTP handler,
two synthetic sessions, real non-extractable X25519 keys and HPKE encryption,
durable storage, restart and local decryption in both directions. Its
authorizers are explicitly synthetic; it does not test the CLI's missing
private UBID transport or real device challenge consumption. X25519 remains
encryption-only; this change generates or stores no Ed25519 private key on
the server.

Remaining gates include the trusted Unix-socket provider, atomic request
admission and lost-response recovery, Enrollment V2 device lifecycle wiring,
the Messages UI, recipient discovery and packages, real independent browser
sessions, and the phone Legacy/QR flow. UBID must supply canonical Current
Full; Social does not grant or override entitlement.
