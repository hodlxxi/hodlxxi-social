# Canonical Social messaging completion plan

Completion means two real Current-Full participants can send, receive, and
locally decrypt private messages. A route check, successful login, registered
public key, staging readiness report, or accepted ciphertext alone does not
meet that product goal.

The three independent boundaries are participant authentication, authorization
of one exact messaging device, and ciphertext messaging. Mobile authorization
must work without NIP-07 and without NIP-46. The public-Nostr **Connect signer**
control remains separate. Every messaging device generates and persists its own
non-extractable X25519 CryptoKey; no participant private key, serialized device
private key, or K_message crosses a transport, DOM, log, URL, or JSON boundary.

## Phase 1: cross-repository device authorization contracts

Phase 1 supplies dormant parser/canonicalization and verification components,
fixed vectors in both repositories, phone key preparation and explicit desktop
approval seams, and the UBID Current-Full timestamp precision correction.
It does not activate mobile login, QR pairing, sessions, or messaging routes.

The normative shared protocol is UBID's
[`docs/SOCIAL_MOBILE_DEVICE_AUTHORIZATION_V1.md`](https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer/blob/staging/docs/SOCIAL_MOBILE_DEVICE_AUTHORIZATION_V1.md).
Use that document together with the matching file in the reviewed UBID worktree
until the source is integrated. The protocol and independently implemented
fixtures are compatible across repositories; neither repository imports the
other's source at runtime or requires it to run its own tests.

The existing canonical device claims remain authoritative. The method envelope
adds exact context for the original LEGACY UUID challenge or the QR transcript.
It cannot change an operation, subject, device key, request, binding version,
predecessor, or expiry without changing the committed digest. Ordinary NIP-07
events retain their existing bytes and signatures. NIP-46 remains an injectable
one-shot signer with no transport or fallback.

For independent phone login, the existing wallet signs the displayed UUID as a
Bitcoin Signed Message. The canonical proposal is immutably reserved against
that challenge before signature, and UBID verifies and atomically consumes the
original record. Successful bound LEGACY login requires no second NIP-07
signature. OAuth/session possession cannot replace that proof. The existing
unbound login and OAuth routes are unchanged in Phase 1.

For pairing, Add phone creates a short-lived one-shot locator/secret. Scanning
creates a pending proposal only. Both devices display a comparison code derived
from the exact transcript. Only explicit Approve phone acquires NIP-07 and calls
signEvent once after an exact session-subject match. UBID acceptance precedes
one-time phone session exchange; the QR contains no authorized login grant. A
separate phone exchange verifier binds that exchange to the transcript without
using the messaging CryptoKey for authentication. The phone subsequently
reconciles its own authoritative binding under its own session.

The Social source additions are not imported into the authenticated entry.
Their enabled flags default to false. Existing browser reconciliation, IndexedDB
cross-tab protections, confidential BFF authentication, public internal-route
denials, and exact accepted retry behavior remain in force.

## Phase 2: complete mobile authorization and session continuity

Integrate immutable challenge issuance/consumption with the real LEGACY login
and original OAuth browser transaction. Extend UBID's existing canonical
evidence, replay and lifecycle storage to carry the new method proof without
mislabeling it as a Nostr signature. Recheck Current-Full and exact predecessor
state in the acceptance transaction. Implement accepted-result recovery without
resigning, then wire the phone's own session and authoritative reconciliation.

Implement pairing offer/revision storage and cancellation, explicit desktop
approval UI, and atomic device-bound exchange/session issuance. Keep QR and
mobile routes default-off until these dependencies are complete. Preserve
register/adopt/rotate/revoke behavior and optional desktop NIP-07. No silent
OAuth-only fallback and no mandatory phone extension are permitted.

## Phase 3: ciphertext transport and inbox completion

Connect accepted Current-Full device authorization to recipient capabilities,
canonical device handles and recipient crypto packages. Complete the existing
ciphertext-only envelope, authorization, routing, storage and inbox contracts.
Keep recipient identity minimization, replay protection, retention limits,
rotation/revocation and sender-device copies explicit. Never send plaintext or
unwrapped K_message to Social or UBID.

## Phase 4: browser encryption, reception and local decryption

Wire the reviewed browser encryption implementation and local device-key
decryption into the authenticated Messages UI. Require authoritative binding
reconciliation before use and preserve clear pending/error states. A new device
does not automatically obtain historical keys. Device revocation cannot erase
already-received ciphertext or keys.

## Phase 5: prove the complete product slice

First verify the whole flow offline using deterministic participants, adapters
and fixed vectors. Separately authorize any environment activation and a
controlled rehearsal with two real Current-Full users, including a phone with
no Nostr extension. Verify send, receive, local decryption, restart continuity,
rotation/revocation and failed authorization. Claim messaging completion only
after that vertical slice succeeds. Source review, staging activation and
production promotion remain separate decisions.

## Phase 3 source prerequisite: accepted mobile routing evidence

The next source increment is partial. UBID's canonical
`docs/SOCIAL_MESSAGING_MOBILE_ROUTING_V1.md` defines its default-off accepted-mobile
proof verifier and read-only adapter over the existing committed acceptance
owner. Social adds `src/server/message-routing-request-v1.mjs`, an inert,
explicitly gated projection from the exact V1.28F.1 wire into UBID's already
reviewed `hodlxxi.social_messaging_recipient_routing_request.v1`. Neither is
imported into runtime composition or the authenticated browser.

The projection first performs the unchanged bounded canonical envelope parse,
then computes the existing domain-separated envelope digest. It returns only
`envelopeDigest`, `messageId`, `recipientDeviceHandles`,
`recipientPackageSnapshotId`, `schema`, and `version`, in compact sorted-key ASCII
JSON, limited to 2,048 bytes. It additionally enforces UBID's existing canonical
base64url handle encoding without changing any handle. It accepts no caller
subject, recipient identity, digest override, alias, key or routing decision.
`enabled` defaults to false and only literal `true` permits projection.
Failures use only `message routing unavailable`. This is a request serializer,
not authentication, transport, a storage receipt or a success response.

The identical `tests/fixtures/social_messaging_phase3_routing_v1.json` in each
repository freezes the real UBID package producer's public result, synthetic
ciphertext envelope, digest and request. Independent consumer tests preserve
repository isolation and prove byte-for-byte compatibility. Existing V1.28E
and V1.28F.1 bytes and Phase 2 authentication behavior are unchanged.

Phase 3 still requires transactionally composed Nostr/mobile proof selection,
exact sender-device/session and recipient-self admission, capability-bound
package issuance with durable confidential routing-snapshot retention, UBID's
routing-registry/decision-ledger migration and adapter, a minimized outward
routing contract, and Social's own ciphertext persistence/submission/inbox.
That work must define atomicity and lost-response recovery across the owners,
replay conflicts, bounded pagination/cursors, retention/quotas, opaque sender
attribution, sender-device copies/history, and future rotation/revocation
retrieval checks. All runtime/client/route wiring and a complete offline
transport/inbox rehearsal remain pending. These dependencies must be completed
before Phase 4 browser encryption/reception/decryption UI work begins.
