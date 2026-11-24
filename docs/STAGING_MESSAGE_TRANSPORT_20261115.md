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

## Registered-device session continuation (2026-11-24)

Paired with UBID #597. The explicitly selected native runtime now composes a
registered-device BFF when both delivery manifests opt into
`registeredDeviceSessions: true`. The browser can prove possession of its retained
Ed25519 key after the original enrollment issuance expires, restore after reload,
and renew before use without pairing again. The credential is scoped to messaging,
kept on the server behind an opaque HttpOnly cookie, and is not an OAuth token.
Current Full and exact device authority remain external UBID decisions.

The registered scope serves the private directory, session-bound recipient
capabilities, recipient packages, exact message challenges, ciphertext send and
inbox. Messages still need their independent Ed25519 request proofs. Registered
login statements use the native Enrollment V2 server statement key/trust with a
new domain; message statements retain their separate configured trust.

Logout revokes the exact scoped session even after Full loss, preserves the
ordinary entry/mobile-CSRF response contract, cancels pending login completion,
and retains a separate HttpOnly denial preference until explicit sign-in (cookie
lifetime one year). No browser storage is cleared and no device key is replaced.
The context and local session maps are bounded. The normal default stays disabled.

Before enabling, apply the two new UBID registered-device migrations and their
closed finalizer permissions; see `docs/social-registered-device-session-v1-plan.md`
in the paired UBID PR. Native finalizer INSERT on the generic challenge table
remains prohibited; a narrow attested definer function stores only scoped device
message challenges. Long-term history retention remains a release prerequisite.

Tests in this repository exercise synthetic service responses plus real Ed25519
proofs, request framing and ordinary entry integration. The paired PG16 workflow
also runs strict Social proof verification against real native SQL history and
registered-session message authorization. Neither test is real Alice/Bob browser
acceptance. Keep #73 and UBID #597 draft and issue #588 open until the complete
funded Full + encrypted chat + phone/independent-browser acceptance succeeds.
