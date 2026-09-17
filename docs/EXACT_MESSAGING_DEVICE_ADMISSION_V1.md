# Exact messaging-device admission: contract and pending decision

Status: **contract only, proposed for review**. There is no approved device
request proof profile. No request can be admitted by this increment, even with
`enabled: true`. No route, session issuer, key, challenge issuer/store, replay
adapter, routing registry, ciphertext store, inbox or UI is added. Candidate
serialization is separately default-off and is not proof verification.

This is the next prerequisite in [the completion plan](MESSAGING_COMPLETION_PLAN.md).
The [key-role policy](SECURE_MESSAGING_V1_28_ARCHITECTURE.md) and AGENTS.md permit
only the dedicated non-extractable X25519 encryption CryptoKey. They explicitly
do not permit using it for authentication or general signing. The existing
architecture calls for future possession proof without specifying a construction.
Historical binding acceptance, QR scan, successful session issuance and local
`ready` state cannot fill that gap.

## Existing primitive map

Paths below are repository-relative; UBID paths identify external read-only
authority. Social neither imports UBID nor grants Current-Full.

| Owner/file | Existing responsibility and limit |
| --- | --- |
| Social `src/server/social-oauth-bff.mjs` | `authenticatedSessionContext` derives subject from the opaque cookie/session, awaits mobile resolution; no request-device possession proof. |
| Social `src/server/social-oauth-memory.mjs`, `social-oauth-cookie.mjs` | Bounded local session lifetime, cancellation and opaque cookie presentation; no device authority. |
| Social `src/server/social-mobile-session-v1.mjs` | `read` resolves the original issuance on each use, rechecks local identity/cancellation/expiry after awaits; `install` cannot use historical handoff as authentication. |
| Social `src/server/social-authority-reader.mjs` | Independent external Full/Limited projection; device registration cannot grant Full. |
| Social `src/server/ubid-messaging-device-client.mjs` | Confidential viewer-authenticated binding snapshots, intents and accepted results; no possession verifier. |
| Social `web/messaging-device-v128c1.mjs` | Non-extractable X25519 `deriveBits` key, IndexedDB structured clone and exact public-binding reconciliation; key never authenticates. |
| Social `web/messaging-device-authorization-v1.mjs`, `mobile-device-authorization-contract-v1.mjs`, `mobile-device-authorization-seams-v1.mjs` | Participant-approved exact binding, original LEGACY/QR contexts, explicit desktop signature and local verification; no per-request device proof. |
| Social `src/server/opaque-recipient-capability-{issuer,resolver}.mjs`, `ubid-messaging-recipient-client.mjs` | Session-bound selected recipient and minimized crypto package; capability is not send authority. |
| Social `src/server/message-envelope-v128f1.mjs`, `message-routing-request-v1.mjs` | Exact envelope wire/digest and default-off six-field routing projection; neither authenticates. |
| UBID `app/services/social_messaging_device_contract.py`, `social_messaging_device_storage.py` | Canonical binding-record ID, version, predecessor, current lifecycle and public X25519 binding. |
| UBID `app/services/social_messaging_device_binding_authorization.py`, `social_messaging_device_binding_authorization_storage.py` | Participant Nostr approval/adoption, exact evidence and transaction-owned lifecycle/replay, independent Current-Full. Approval is not possession. |
| UBID `app/services/social_messaging_mobile_authorization.py`, `social_messaging_mobile_authorization_storage.py` | Original LEGACY/QR proof verification and accepted mobile ownership; scan and historical acceptance cannot authorize a new request. |
| UBID `app/services/social_session_issuance.py`, `oauth_session_lifecycle.py` | Original parent/phone session provenance, current resolve and invalidation; canonical bearer remains authentication only. |
| UBID `app/services/social_messaging_mobile_routing.py`, `social_messaging_mobile_routing_storage.py` | Exact committed accepted evidence, distinct mobile proof namespace; expressly no sender admission. |
| UBID `app/services/social_messaging_recipient_routing.py`, `recipient_device_resolver.py` | Pairwise handles, exact package/request bytes, both participants' Full checks; confidential routing repository remains a port. |
| UBID `app/services/current_entitlement_evidence_storage.py`, `current_full_entitlement_proof.py` | Transaction-bound Current-Full verification and canonical typed evidence. |

The relevant UBID normative documents are `SOCIAL_MOBILE_DEVICE_AUTHORIZATION_V1.md`,
`SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1.md`, `SOCIAL_SESSION_ISSUANCE_V1.md`,
`SOCIAL_MESSAGING_RECIPIENT_ROUTING_V1.md` and `SOCIAL_MESSAGING_MOBILE_ROUTING_V1.md`
under its `docs/`. The last two explicitly leave request possession unresolved.

## Decision deferred

| Choice | What it proves / cost | Policy status |
| --- | --- | --- |
| Separate non-extractable messaging authentication CryptoKey | Signs a domain-separated exact request challenge; preserves encryption/authentication separation and allows phone use without participant signer access. Requires new public-key authorization, explicit association with the exact encryption binding, device-local structured-clone permission, rotation/revocation and browser compatibility review. | **Recommended for review**, not approved or implemented. Algorithm, signature encoding and signed proof envelope remain unset. |
| Reviewed encryption-key challenge/response, potentially using the existing HPKE suite | Could demonstrate decryption/key-agreement possession for the exact encryption key. Requires a new authentication protocol, domain separation, challenge-oracle and cross-protocol analysis; existing HPKE message wrapping does not authorize it. | Requires an explicit change to the encryption-only key policy; not implemented. |
| Device-bound platform credential | Could provide request signatures with platform key protection. Must establish device-specific, non-synced ownership, browser support, exact enrollment and loss/rotation behavior; a generic synced credential does not prove this device. | Separate policy/protocol decision, not implemented. |

Participant signatures on every request prove participant control, not possession
of the exact messaging device, and cannot require phone NIP-07/NIP-46. Bearer
secrets, saved QR/exchange verifiers, caller-provided device IDs and server-held
device private keys are not options. No key material is generated here.

Approval must explicitly select a proof profile and authorize its local key
policy, enrollment and binding association. With the recommended option, both
public keys must be approved in one exact association, with proof of possession
of the new authentication key at enrollment. This must be a versioned extension,
not a reinterpretation of existing signed binding bytes or IDs. Every change
to either key invalidates the association and outstanding challenges. Existing
devices require explicit enrollment; OAuth cannot silently attach an auth key.
This authenticates the approved device association; it does not independently
prove X25519 private-key possession on every request. Review must accept that
distinction or require an additional separately reviewed enrollment proof.

## Candidate request and challenge bytes

`src/server/messaging-device-admission-v1.mjs` is the only candidate serializer.
All its helpers require literal own-data `enabled: true`; default is false.
Inputs are bounded canonical ASCII JSON strings, never caller object graphs.
Exact round-trip checks reject duplicate/unknown/missing keys, alternate escapes,
whitespace, numeric variants and Unicode. Output fields are sorted lexically,
compact, with no trailing newline. Parsed outputs are frozen flat records.

The confidential context is at most 1,024 bytes and contains exactly:

```text
audience, bindingId, bindingVersion, deviceId, sessionBinding, subject
```

`audience` is the exact trusted canonical HTTPS Social origin, at most 255 bytes.
Subject/device/binding/sessionBinding are lowercase hex64; bindingVersion is an
integer 1..1024. A future trusted session adapter assigns `sessionBinding` as a
non-secret, non-bearer per-session-generation correlation value and binds it to
the original canonical authentication owner. It is never the cookie, access
token, token hash, OAuth client assertion or caller's session selector. That
adapter and any required persistence are deferred. Another login of the same
subject must have a different binding; logout/replacement invalidates challenges.

The request candidate is at most 2,048 bytes and contains exactly those six
context fields plus:

```text
bodyDigest, method, operation, path, recipientHandle, schema, version
schema = hodlxxi.social_messaging_device_request_candidate.v1
version = 1
```

Only method `POST` and operations `ciphertext-submit` / `recipient-self-read`
are proposed. Paths have at most 160 ASCII bytes and match
`^/[a-z0-9]+(?:[/-][a-z0-9]+)*$`; no query, fragment, percent encoding, dot segment,
trailing slash or normalization is allowed. Fixture paths are illustrative,
unregistered paths. A future route adapter must supply the actual method and
raw target and independently allowlist its operation/path tuple. The serializer
cannot establish which route was used. No HTTP route is selected or installed.

For submission, the body is the **unchanged exact V1.28F.1 envelope wire**
(maximum 32,768 bytes); `recipientHandle` is null. The existing envelope parser
validates it before hashing. Do not sort its fields or hash only its routing
projection. For self-read, the body is at most 256 bytes, exactly sorted JSON
`{deviceHandle,schema,version}`, with schema
`hodlxxi.social_messaging_recipient_self_request.v1`, version 1 and one existing
canonical `d_` handle (16 bytes, unpadded base64url). `recipientHandle` repeats
that exact body handle. No raw subject, lookup key, arrays, wildcard, pagination
or cursor is accepted. Pagination will require a separately reviewed body
version that binds all selection/limit/cursor fields into the digest.

```text
bodyDigest = "hodlxxi-social-device-request-body-v1-sha256:" +
  hex(SHA256(ASCII("HODLXXI_SOCIAL_DEVICE_REQUEST_BODY_V1") || NUL || bodyWire))
```

This is a request-body commitment, not the existing envelope digest. The existing
six-field UBID routing request, binding IDs, Nostr/mobile proof IDs, package IDs
and pairwise handles stay byte-for-byte unchanged.

The challenge candidate is at most 4,096 bytes, exactly:

```text
challengeId, domain, expiresAt, issuedAt, request, schema, version
domain = HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1
schema = hodlxxi.social_messaging_device_challenge_candidate.v1
version = 1
request = exact canonical request STRING (JSON escaped once)
```

Times are nonnegative safe-integer UTC epoch milliseconds, with
`issuedAt <= now < expiresAt` and `0 < expiresAt-issuedAt <= 60,000`. No clock
skew or expiry grace. Challenge ID is 32 fresh CSPRNG bytes as lowercase hex64
from the future authoritative issuer, globally reserved in namespace
`social-device-request-challenge-v1:<challengeId>` before release. Fixture IDs
are synthetic; the current helper only serializes and never issues/reserves.
The inspection helper compares the entire newly reconstructed actual request
byte-for-byte and checks time. It does not authenticate, consume or grant.

```text
challengeDigest = "hodlxxi-social-device-challenge-v1-sha256:" +
  hex(SHA256(ASCII("HODLXXI_SOCIAL_DEVICE_CHALLENGE_DIGEST_V1") || NUL || challengeWire))
```

This digest is a content identity, not a credential or a selected signature
preimage. The future approved proof profile must commit all exact challenge
bytes and its own algorithm/key/domain identity. There is no default profile,
signature parser, permissive verifier or algorithm fallback.
`tests/fixtures/social_messaging_device_admission_v1.json` freezes both complete
request/challenge wires, lengths and digests using independent Python standard
library canonicalization. They are contract vectors, not valid device proofs.

## Required verifier interfaces and atomic owner

JSDoc interfaces `DeviceProofVerifierV1` and `DeviceAdmissionAuthorityV1` describe
deferred ports. No injected implementation is accepted by the admission stub.
Their required semantics are:

1. `lockAndReadCurrent(trustedAuthentication)` resolves the current original
   session and independently verifies Current-Full for its exact subject. It
   reads a complete, untruncated authoritative device set, rejecting missing,
   duplicate/ambiguous device IDs, binding IDs, public keys, versions or evidence.
   Exactly one current active binding must equal subject/deviceId/bindingId/
   version and have exact independently verified accepted Nostr **or** mobile
   authorization, not both. Reverify with the existing respective verifier;
   never relabel proof namespaces. The approved authentication-key association
   must match that same complete binding. Public keys remain confidential here.
2. `readIssuedChallenge(challengeId)` requires exactly one immutable original
   reservation owned by that session, binding and approved profile. Caller JSON
   cannot replace it. Challenge expiry must also be bounded by session, Full,
   binding, accepted evidence and approved key-association deadlines.
3. `verifyInTransaction(exactChallengeWire, profileSpecificProof, lockedAuthority)`
   returns an immutable verified record with exactly `challengeDigest`,
   `proofProfile`, `sessionBinding`, `subject`, `deviceId`, `bindingId`,
   `bindingVersion`. Every field must match the reserved transcript and approved
   association, using the authority's public key, never a supplied replacement.
   A boolean, historical proof, digest, session, service credential or key
   equality is insufficient. The proof encoding remains undefined until approval.
4. `resolveRecipientSelf(handle, lockedAuthority)` is required only for self-read
   and returns one exact confidential registry mapping as specified below.
5. `consumeAndApply(exactOperation)` rechecks time and current session/Full/
   lifecycle/evidence/key association after lock waits and verification, consumes
   the challenge exactly once and performs the authorized authority operation in
   the **same** transaction. Failures roll back without an outward grant. All
   calls must share this owner; detached verifiers and caller snapshots fail.

The future UBID transaction must reuse the existing Current-Full subject, User,
device, public-key and lifecycle lock domains. Its complete lock order and
interaction with session/registry writers require review and race tests before
implementation. No independent Social cached Full decision may replace this.
An admission that linearized before revocation may finish; there is no claim of
instantaneous cancellation of already returned ciphertext. Every subsequent
request rechecks current authority; restored Full cannot resurrect a consumed
challenge or a revoked session/device/key association.

The global replay owner rejects repeated identical requests as well as changed
ones: no accepted-result replay bypasses current checks. Challenge replay is
distinct from the existing message-ID/digest idempotency ledger. A lost response
requires a new proof/challenge and current checks for the same exact operation;
future message idempotency may recover the same committed result without a
second message. Cross-owner UBID/Social atomicity and confidential result
delivery are not implemented. No portable bearer admission token is proposed.

## Sender and recipient-self behavior

Sender admission requires the current session subject and exact current accepted
sender binding, current Full, approved request proof and single-use challenge
before the unchanged routing projection can acquire authority. Recipient Full,
package/capability and exact routing authorization remain additional checks.
An envelope contains no sender proof; it cannot authenticate itself.

Self-read proves the same device association under its own current session and
Full status. The confidential registry must require
`mapping.recipientSubject == session.subject`, `mapping.deviceId == deviceId`,
and `mapping.bindingId/bindingVersion == current binding`. It must have exactly
one active namespace/ownership result for the requested handle. No match,
ambiguous match, another device of the same subject, another subject, old binding,
rotation, revocation or unknown namespace all fail identically. Request-body
handle substitution changes the commitment and fails comparison/proof.

Existing handles are **sender-viewer-pairwise**. Recomputing with viewer=self
would produce different bytes and is forbidden. The future registry retains
the exact sender-viewer namespace and recipient binding mapping at package
issuance. A device can own multiple pairwise handles, but any discovery must be
scoped by its already proven current binding, never subject-only or arbitrary
handle enumeration. This contract exposes no discovery endpoint, raw participant
key lookup or cross-device inbox access. Challenge preparation cannot reveal
handle existence before device proof; authorization failures use one shape and
must be rate-bounded in future ingress.

The confidential transcript and verifier state contain identity; they must not
be copied into routing outputs, ciphertext rows, URLs, logs or telemetry. A
future minimized result may carry only the exact approved opaque operation
scope over authenticated confidential delivery; that result contract is deferred.
The current sole failure is `messaging device admission unavailable`, with no
input/dependency details. `admitMessagingDeviceRequestV1` always throws it and
never calls authority or cryptography, including with apparently valid evidence.

## Work still required

Approve the proof profile/key policy and enrollment association; implement and
test browser proof, UBID verifier, session-generation binding, atomic challenge/
replay owner and lifecycle races. Then implement confidential routing-registry
retention and recipient-self ownership, capability-bound package issuance,
minimized operation results and cross-owner lost-response/idempotency semantics.
Only then add Social ciphertext persistence, bounded inbox/cursors, quotas,
retention and sender-copy/history policy, default-off ingress/runtime wiring,
and complete offline lifecycle rehearsal. Phase 4 encryption/reception UI and
any activation remain separate. These candidate tests do not claim admission,
delivery, decryption or full messaging completion.
