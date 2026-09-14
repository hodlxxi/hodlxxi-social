# Dormant Social mobile consumer V1

The canonical contract is UBID `a8c409dbe4c900cc8f99c08346cd15bf83604336`. The two new contract fixtures are byte-for-byte copies of that commit. The issuance fixture maps Social base `3116db8f7f257b677782e2654340d61c49ac537b`; tests check those immutable Git blobs. The Phase-1 fixture is unchanged.

The implemented journey is desktop offer, phone proposal/scan, comparison, explicit desktop approval, exact saved approval retry, status/close, phone reconciliation, exchange, separate issuance/recovery, authenticated use, and logout. LEGACY reserve/accept/status/close remains bound to desktop OAuth; it has no QR session issuance. Existing NIP-07 authorization is separate.

No normal CLI, browser entrypoint, discovery or configuration installs this composition. A trusted caller must explicitly construct the confidential clients, call `createSocialMobileComposition({enabled:true,...})`, pass its `mobilePostRoutes` to `createHttpHandler`, and explicitly mount `mountSocialMobileAuthorization`. Off/absent leaves the original BFF in place. The UI accepts a pairing locator; camera scanning and physical-phone E2E are deferred.

## Source and authority map

| Source | Responsibility |
| --- | --- |
| `web/social-mobile-protocol-v1.mjs` | Closed schemas, duplicate-member/depth/size checks, canonical dates and historical identity inspection |
| `src/server/ubid-social-mobile-client-v1.mjs` | Separate confidential mobile/issuance clients, fresh RS256 assertions and fixed Unix-socket requests |
| `src/server/social-mobile-bff-v1.mjs` | Fixed routes, exact Origin/CSRF, immutable phone context, original proof reconciliation and logout |
| `src/server/social-mobile-session-v1.mjs` | Current resolution, one local presentation per issuance, absolute expiry, exact original-credential cancellation |
| `src/server/social-oauth-memory.mjs` | Existing bounded store with validated absolute mobile records and cancellation-only retention |
| `src/server/social-oauth-bff.mjs` | Awaited authentication helpers and every caller, including `/auth/session`; enabled OAuth callback fence |
| `src/server/opaque-recipient-capability-{issuer,resolver}.mjs` | Optional awaited `sessionReader`; inject composition's `capabilitySessionReader` for mobile. Without it, the existing closed four-field reader denies mobile records. |
| `scripts/hodlxxi-social-server.mjs` | Explicit route body allowlist, actual wire-header cardinality, bounded fatal UTF-8 reading and framing |
| `web/social-mobile-browser-v1.mjs` | Explicit controllers, Phase-1 key/signature seams, transient phone proofs, public signed retry persistence |
| `web/social-mobile-ui-v1.mjs` | Explicit UI, comparison/approval/recovery/logout actions and deadline disclosure |
| `web/messaging-device-v128c1.mjs` | Atomic comparison-and-delete of an unaccepted pending registration after explicit authoritative cancellation/rejection |

Authentication calls S/resolve before installing and on every later mobile use. This covers session/authority projections, read/publish configuration, Full Directory, recipient capability/package and device configuration/binding/authorization. Capability issuer/resolver must receive the trusted asynchronous reader to accept mobile records. Each call compares receipt, subject, exact local object and absolute dates, then rechecks cancellation, presence and expiry after the await. No successful response is cached for the next request. An operation admitted before revocation can finish; no remote transaction spans browser delivery.

## Exact routes and credentials

M is `/internal/v1/social/mobile-authorization`; S is `/internal/v1/social/session-issuance`. Token grant forms use fresh confidential client assertions with the exact service-token URL audience. Mobile scopes are `social:mobile-authorization:desktop`, `:phone`, `:exchange`, `:invalidate`; issuance uses `social:session-issuance:manage`. UBID validates the distinct resource audiences, purposes and live credential eligibility. Full Directory permissions are never reused.

The confidential bearer occupies `Authorization`. Desktop/invalidation commands carry the original human OAuth credential only in `X-HODLXXI-Viewer-Authorization`. Phone/exchange and issue/recover omit that header. Resolve/revoke use the original mobile viewer there. No backend assertion, infrastructure key or viewer/service bearer reaches the browser. The browser cannot select an upstream transport, scope, path, subject override or session ID.

All new routes are POST under `/auth/mobile/v1`, with exact configured Origin, bounded JSON, no query and `x-hodlxxi-mobile-csrf` except context bootstrap:

| Suffix | UBID command and exact string fields |
| --- | --- |
| `/context` | Local `{}`; opaque host cookie and CSRF binding |
| `/legacy/reserve` | M/legacy/reserve: `content` |
| `/legacy/accept` | M/legacy/accept: `operationId,authorizationDigest,proof` |
| `/legacy/status` | M/legacy/status: `operationId` |
| `/legacy/close` | M/legacy/close: `operationId,status` |
| `/qr/create` | M/qr/create: `{}` |
| `/qr/offer` | M/qr/offer: `qr` |
| `/qr/scan` | M/qr/scan: `source,qr,possessionProof` |
| `/qr/snapshot` | M/qr/snapshot: `pairingId,revision` |
| `/qr/claim` | M/qr/claim: `pairingId,revision,authorizationDigest,humanCode` |
| `/qr/accept` | M/qr/accept: `pairingId,revision,authorizationDigest,proof` |
| `/qr/status` | M/qr/status: `pairingId` |
| `/qr/close` | M/qr/close: `pairingId,status` |
| `/phone/status` | M/phone/status: `pairingId,revision,authorizationDigest,verifier` |
| `/phone/recover` | M/phone/recover: `source,qr,possessionProof,verifier,revision` |
| `/phone/exchange` | M/phone/exchange: `pairingId,revision,authorizationDigest,verifier` |
| `/session/issue`, `/session/recover` | S/issue or S/recover: `pairingId,revision,authorizationDigest,verifier,deliveryKey` |

Desktop operations require a current local desktop session. A mobile child cannot act as an approving desktop. Enabled `/auth/logout` uses the same bound CSRF and `{}` to choose S/revoke `{issuanceId}` or M/oauth/invalidate `{}` from the retained original credential. There is no browser S/resolve route. QR acceptance `proof` is the exact canonical signed event; the persisted browser retry wrapper is not sent as UBID's proof.

The closed historical handoff fields are `schema,version,identity,operation,revision,consumedAt,delivery,freshIssuanceAuthorized`. Identity fields are exactly `schema,version,pairingId,authorizationDigest,bindingId,deviceId,subject,requestId,exchangeCommitment,expiresAt`. They are compared against the original canonical QR source and verifier commitment. `freshIssuanceAuthorized` remains false even for `delivery:"created"`. Scan, claim, acceptance and historical exchange JSON do not authenticate.

S/issue and S/recover return exactly `{receipt,currentActive,subject,viewerAccessToken}`; inactive is false/null/null. Receipt is `{schema:"hodlxxi.social_session_issuance.v1",version:1,issuanceId,issuedAt,expiresAt}`. Installation requires the active credential and exact S/resolve `{receipt,subject,currentActive:true}`. Revoke acknowledgment is `{schema:"hodlxxi.social_session_revocation.v1",version:1,issuanceId,status:"revoked"}`. Desktop acknowledgment uses the frozen generation-invalidation schema/version and `status:"invalidated"`.

## Presentation, recovery and replacement

UBID owns all durable issuance and replay decisions. Social adds no database, migration, durable authorization ledger or bearer scheme. Mobile records are `{kind:"ubid-mobile-v1",subject,viewerAccessToken,issuanceId,issuedAt,expiresAt}`. UTC whole-second wire dates become exact absolute milliseconds. The original opaque `__Host-hodlxxi-social-session` Secure/HttpOnly/SameSite=Lax cookie carries a random alias. Its Max-Age is floored to remaining seconds; less than one complete second denies installation. Existing desktop TTL behavior is unchanged.

The original pairing-window cap remains **at most five minutes from offer creation**, shortened by parent, binding or semantic expiry. Completion does not restart the clock. There is no refresh/renewal.

Concurrent equal completions serialize and reuse one alias per issuance. Lost local delivery returns the same effective presentation. Restart/cache eviction makes an old cookie unauthenticated. Only original verifier/deliveryKey proofs can ask S/recover for the same already-issued token/receipt/deadline and allocate a new local alias. Missing proofs and missing retained credential mean terminal local delivery loss. Historical JSON or an old cookie cannot recreate authority.

Maps default to 1024 entries; the explicitly supplied session store retains its configured capacity. Phone contexts are bounded at 1024 and ten minutes, including reconciliation/cancellation retention. Expired mobile credentials are retained at most five extra minutes only for original-credential logout. Neither retention extends authority. Capacity failure never returns authentication; the original returned credential remains in bounded transaction memory for reconciliation/cancellation. Process loss loses that retry context.

Logout denies local use before awaiting upstream. Denial is recorded in the already allocated session-store slot, independently of retry-map or serialization capacity. The ordinary `get` and `consume` paths never return a denied record. If the cancellation map is full, the slot retains only the original credential and fixed five-minute cancellation deadline for exact retry; a confirmed overflow acknowledgement can stay in that same denied slot. Repeating logout never extends this deadline. These entries still count against the existing session-store capacity. Saturation can refuse new local presentations, but cannot resurrect a logged-out one or discard another pending cancellation. Expiry removes the entire denied slot. The regular cancellation map remains bounded by its configured capacity. Pending/unconfirmed is explicit; success requires the exact durable acknowledgment. Retried cancellation retains the original credential even if expired/revoked. An in-flight issuance cannot produce confirmed logout before its identity is known; a late returned credential is denied and cancelled exactly. No-session logout is explicitly `local-only`. Old replies cannot select a replacement by subject. Enabled OAuth login requires context bootstrap and no current presentation; same- and different-subject replacement both require explicit logout. The callback fence denies installation after context cancellation. Disabled composition preserves old desktop logout. UBID stale-cookie logout cleanup remains separate required pre-activation work.

## Device and privilege boundary

Phase-1 non-extractable X25519 keys remain device-local IndexedDB structured clones. No participant Bitcoin/Nostr/UBID private key is requested, transmitted, logged or persisted. NIP-07 is acquired only on explicit approval, checks the extension key against the subject, claims first, and signs once. The public signed retry is stored separately in IndexedDB. Poll/recovery never requests another signature.

An independent random deliveryKey is generated before issuance and held with the original verifier in the controller, never storage/URLs/logs. Interrupted awaits preserve the pending key and proposal. A fresh controller finding a key without original transient proofs fails closed and requires recovery/new login. Only authoritative irreversible cancellation/rejection of the exact proposal permits deliberate local deletion; never-accepted, expiry and logout do not. The key is not authentication evidence. Messaging stays `not-ready`; mobile proof is not relabeled as Nostr evidence.

Full/operator/sponsor/CRT/covenant/friendship/directory state is never mutated. Full requires independent current evidence and existing downstream checks. Limited and operator-shaped assertions cannot acquire Full through mobile authorization.

## Tests and Phase 3

The focused Node suites cover real schemas, session/BFF boundaries and disposable Unix HTTP. The unchanged Phase-1 suite covers explicit signatures, non-extractability and structured cloning. Browser storage/DOM are simulated; this is not a physical-phone E2E claim.

`python3 tests/support/social-mobile-ubid/run.py --output /tmp/<new-owned-directory>` requires explicit disposable PostgreSQL authorization. It uses the existing verified environment, an owned archive of pinned UBID, and SQLite/IP/Unix guards self-tested before application imports and inherited by children. The real JavaScript controllers/BFF/Unix clients consume actual verified OAuth/QR/signature/issuance services. The test-only external signer holds the synthetic participant key outside Social; only public events cross the socket. It records app exit separately from interpreter shutdown and removes its owned cluster/scratch. `--only-js` omits already-passed pinned boundary regressions.

Phase 3 still needs independent review, explicit credential/scope and Unix ingress provisioning, actual browser cookie/IndexedDB/NIP-07/phone tests, capacity/restart and pending-logout UX review, UBID stale-cookie logout cleanup, downstream mobile messaging evidence integration, and separately authorized activation. No runtime activation is authorized by this source change.
