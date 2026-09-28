# Exact messaging-device proof and verification statement: dormant; admission pending

Status: **proof profile, Enrollment V2, the strict Social verification-
statement producer, the accepted-binding browser key prerequisite, and the
separate provisional V2 preacceptance compatibility slice are implemented as
dormant, default-off contracts; runtime admission remains unavailable**.
The operator has approved a narrow separate Ed25519 exact-device
authentication-key role. This source freezes and strictly verifies the proof
profile, but no runtime admission implementation is enabled. No request can be
admitted by this increment, even
with `enabled: true`. No route, session issuer, server-held key, challenge issuer/store,
replay adapter, routing registry, ciphertext store, inbox or UI is added.
Candidate serialization and strict proof verification remain unimported by
runtime composition. A cryptographically valid result is not replay-protected
admission.

This is the next prerequisite in [the completion plan](MESSAGING_COMPLETION_PLAN.md).
The [key-role policy](SECURE_MESSAGING_V1_28_ARCHITECTURE.md) and AGENTS.md
preserve the dedicated non-extractable X25519 CryptoKey as encryption-only and
forbid using it for authentication or general signing. They separately permit
the narrow Ed25519 role below; the proof construction and dormant browser key
boundary are now frozen but remain unwired. Historical binding acceptance, QR
scan, successful session issuance, browser session, device possession and
local `ready` state cannot fill that gap.

## Operator-authorized Ed25519 policy boundary

The permitted role is exactly one separate, browser-generated Ed25519 WebCrypto
keypair per messaging device. Its private CryptoKey must be
`extractable=false`, remain browser-local, persist only through the approved
device-local browser storage boundary, and never be exported, serialized,
transmitted, or held by Social or UBID. The key is used only for
domain-separated exact messaging-device authentication and proof of possession;
it is never used for encryption, participant/Nostr identity, ordinary Nostr
event signing, Bitcoin, funds, covenant or wallet authority, or general-purpose
signing. The existing X25519 key remains a separate non-extractable,
browser-local, encryption-only key and cannot authenticate, identify, or sign.
The frozen profile identifier is
`hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1`. Public keys are
exactly 32 raw bytes encoded as 64 lowercase hexadecimal ASCII characters.
Signatures are exactly 64 raw bytes encoded as 128 lowercase hexadecimal ASCII
characters. Uppercase, prefixes, padding, whitespace and alternate encodings
are rejected.

There is one current active Ed25519 authentication-key association per exact
messaging device. Controlled rotation may create a successor during an atomic
transition; after rotation only the successor is current. The Ed25519 private
CryptoKey and its record/schema/lifecycle must remain separate from the X25519
encryption-key record/schema/lifecycle. Neither key may be derived from, aliased
to, or substituted for the other. The dormant browser prerequisite selects a
dedicated device-local database, store, schema and immutable record shape for
the Ed25519 key, separate from the X25519 database and store. It does not select
or activate a live association, server-side association storage, rotation
lifecycle, runtime integration or admission path.

Enrollment V2 is a new versioned, domain-separated commitment covering the
exact accepted messaging-device binding, its X25519 public binding, the exact
Ed25519 authentication public key, and the exact versioned Ed25519 proof-profile
identifier frozen above and covered by fixed vectors. This increment selects
and freezes the serializer, preimages, encodings and wire bytes below and adds
only the dormant device-local key prerequisite. Association lifecycle and
runtime activation remain absent.

The exact association must receive one explicit approval from the authorized
external signer whose participant public key exactly matches both the
authenticated session subject and the Enrollment V2 subject. Social must locally
verify the returned approval event and exact subject match, then release the
signer/provider after that explicit approval. Full entitlement is necessary but
insufficient. No different Full participant, sponsor, recipient, operator,
administrator, or OAuth session may approve the association. The phone must
prove possession of the corresponding private key over the same Enrollment V2
commitment and a fresh server-originated challenge. OAuth session, QR scan,
browser session, or device possession alone is insufficient. An existing Phase 2
device cannot receive an unsigned post-acceptance key attachment; it must
explicitly re-enroll or re-pair. Rotation and revocation invalidate the old
association and outstanding challenges.

Runtime admission is disabled/default-off until all of the following exist:

1. Strict Ed25519 public-key and signature validation rejects malformed,
   non-canonical, identity, low-order, and torsion cases. **Implemented in pure
   Social source.**
2. An atomic single-use challenge owner exists.
3. Final admission rechecks the current session, Full entitlement, exact
   association, expiry, rotation, and revocation.

The reviewed cross-repository authority model now selects UBID as the future
owner of challenge storage, single-use consumption, Ed25519 association
lifecycle, rotation/revocation invalidation, exact operation effects, and final
admission. Social remains the strict cryptographic verifier. The dormant Social
producer can emit the frozen purpose-bound RS256 verification statement only
after the real verifier succeeds. UBID's consumer-side byte contract is frozen,
but its authenticated RSA verification and final transactional composition are
future work. No final admission path exists in this increment.

Runtime activation remains blocked until UBID independently authenticates the
statement under a dedicated trust registration and, in one authoritative
transaction, consumes the exact immutable challenge and performs every current
session, Current-Full, accepted-binding, key-association, rotation/revocation,
deadline, request, and operation recheck. An unsigned boolean, caller assertion,
historical result, browser claim, or ordinary service assertion from Social is
never proof authority.

Native WebCrypto/OpenSSL signature verification alone is not the full server
validation boundary. Chrome 137+ is required unless a later separately
reviewed compatibility decision expands support. Any use outside exact
messaging-device proof requires a new explicit operator policy decision.

The following is operator-observed manual preflight evidence, not automated CI
and not runtime activation: Chrome 152 created a separate Ed25519 key with
`extractable=false`; PKCS8 and JWK private-key export attempts were rejected;
32-byte public keys and 64-byte signatures worked; and the key was persisted
through a strict IndexedDB transaction. After fully quitting and reopening as
Chrome 153, the same public-key digest remained
`e58d7fe652ebdcc6a5ffaa8416dd15cdb529148096105935faed81fb68ebe602`. The
persisted private key remained non-extractable and usable. The isolated
preflight database was deleted, and no application database was touched.

## Dormant browser-local Enrollment V2 prerequisite

`web/messaging-device-ed25519-key-v1.mjs` is an explicitly instantiated module
that is not imported by any runtime entrypoint. Its runtime-enabled constant is
false. It opens database
`hodlxxi-social-messaging-device-ed25519-key-v1`, version 1, with object store
`authentication-key`; both are distinct from the X25519 database and `device`
store. The one `current` record contains the exact subject, device ID, accepted
X25519 binding ID/version and public-key commitment, the raw lowercase-hex
Ed25519 public key, and the non-extractable private `CryptoKey`. It is persisted
only by IndexedDB structured clone under a strict-durability transaction. There
is no private-key JSON serialization, localStorage, sessionStorage, network,
logging, private-key export, deletion, update, migration or rotation path.

Preparation requires the current browser context to remain the same Full
subject and requires a current local `ready` X25519 record with its exact
unexpired accepted binding. IndexedDB `add` supplies atomic first-writer-wins
creation across tabs. A losing concurrent creator can use only the already
stored record after every identity and binding field matches; another subject,
device or binding cannot overwrite the slot. The module rechecks the subject
after every asynchronous boundary. Public preparation output never contains
the private `CryptoKey`. Merely storing or possessing the key does not create,
approve or prove a current UBID association.

The sole signing operation accepts one exact canonical Enrollment V2 wire. It
checks enrollment subject, device, X25519 binding ID/version and commitment,
and Ed25519 public key against the current context and separate local records,
checks freshness, and signs only the frozen Enrollment V2 phone-proof preimage.
After signing it rereads and compares the current context, X25519 binding and
Ed25519 record before returning the exact proof wire. There is no arbitrary
signing operation and no device-request signing operation. Request proof still
requires a future authoritative current association and runtime composition.

## Dormant provisional preacceptance V2 compatibility slice

The additive [V2 preacceptance contract](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md)
creates its separate non-extractable Ed25519 key before desktop approval and
binds it to the exact pending X25519 register proposal. Its only state is
`prepared-provisional`; it neither reinterprets this document's accepted-binding
V1 store nor implements promotion, readiness, acceptance or association
authority. A strict-durability signing claim prevents ambiguous retries from
reopening NIP-07, and an exact public signed-attempt artifact is persisted before
return. The private approval event is locally verified and never published.

The matching pure server verifier reparses the exact merged preaccepted-
enrollment V2 wire, verifies BIP340 and the existing strict non-ZIP-215 Ed25519
phone proof, and returns only module-private branded cryptographic evidence.
It emits no V2 verification statement and grants no authority. All V1 bytes and
semantics in this document remain unchanged.

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
| Social `web/messaging-device-ed25519-key-v1.mjs` | Separate dormant non-extractable Ed25519 `sign` key, distinct IndexedDB structured clone, atomic exact-device creation and Enrollment V2-only phone proof; no association, request signing, runtime import or admission. |
| Social `web/messaging-device-ed25519-key-v2.mjs`, `mobile-device-authorization-{contract,seams}-v2.mjs` | Logically separate pending-proposal V2 key lifecycle in its own store within the shared browser-device database, with exact two-store X25519/create-or-claim atomicity, exact merged preacceptance bytes, one explicit private desktop approval and immutable retry evidence; prepared-provisional only, with no publish, dispatch, promotion or runtime import. |
| Social `web/messaging-device-authorization-v1.mjs`, `mobile-device-authorization-contract-v1.mjs`, `mobile-device-authorization-seams-v1.mjs` | Participant-approved exact binding, original LEGACY/QR contexts, explicit desktop signature and local verification; no per-request device proof. |
| Social `src/server/opaque-recipient-capability-{issuer,resolver}.mjs`, `ubid-messaging-recipient-client.mjs` | Session-bound selected recipient and minimized crypto package; capability is not send authority. |
| Social `src/server/message-envelope-v128f1.mjs`, `message-routing-request-v1.mjs` | Exact envelope wire/digest and default-off six-field routing projection; neither authenticates. |
| Social `src/server/messaging-device-proof-profile-v1.mjs` | Current strict Ed25519 primitive implementation, frozen proof/Enrollment V2 bytes, local approval-event verification and phone proof-of-possession; dormant and not an admission owner. |
| Social `src/server/messaging-device-preaccepted-enrollment-v2.mjs` | Additive strict parser/verifier for exact V2 preacceptance plus Enrollment V2, returning only branded cryptographic evidence; no JWS, authority, challenge consumption, persistence or runtime import. |
| Social `src/server/messaging-device-verification-statement-v1.mjs` | Pure default-off producer for the frozen purpose-bound RS256 statement. It invokes the real Social verifier, owns no key or I/O, consumes no challenge, evaluates no current authority, and cannot grant admission. |
| UBID `app/services/social_messaging_device_contract.py`, `social_messaging_device_storage.py` | Canonical binding-record ID, version, predecessor, current lifecycle and public X25519 binding. |
| UBID `app/services/social_messaging_device_binding_authorization.py`, `social_messaging_device_binding_authorization_storage.py` | Participant Nostr approval/adoption, exact evidence and transaction-owned lifecycle/replay, independent Current-Full. Approval is not possession. |
| UBID `app/services/social_messaging_mobile_authorization.py`, `social_messaging_mobile_authorization_storage.py` | Original LEGACY/QR proof verification and accepted mobile ownership; scan and historical acceptance cannot authorize a new request. |
| UBID `app/services/social_session_issuance.py`, `oauth_session_lifecycle.py` | Original parent/phone session provenance, current resolve and invalidation; canonical bearer remains authentication only. |
| UBID `app/services/social_messaging_mobile_routing.py`, `social_messaging_mobile_routing_storage.py` | Exact committed accepted evidence, distinct mobile proof namespace; expressly no sender admission. |
| UBID `app/services/social_messaging_recipient_routing.py`, `recipient_device_resolver.py` | Pairwise handles, exact package/request bytes, both participants' Full checks; confidential routing repository remains a port. |
| UBID `app/services/current_entitlement_evidence_storage.py`, `current_full_entitlement_proof.py` | Transaction-bound Current-Full verification and canonical typed evidence. |
| UBID `app/services/social_messaging_device_proof_profile.py` | Byte-identical shape/serialization consumer only; explicitly does not evaluate Ed25519 or claim final authority. |

The relevant UBID normative documents are `SOCIAL_MOBILE_DEVICE_AUTHORIZATION_V1.md`,
`SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1.md`, `SOCIAL_SESSION_ISSUANCE_V1.md`,
`SOCIAL_MESSAGING_RECIPIENT_ROUTING_V1.md` and `SOCIAL_MESSAGING_MOBILE_ROUTING_V1.md`
under its `docs/`. The last two explicitly leave request possession unresolved.

## Policy decision and remaining alternatives

| Choice | What it proves / cost | Policy status |
| --- | --- | --- |
| Separate non-extractable messaging authentication CryptoKey | Signs a domain-separated exact request challenge; preserves encryption/authentication separation and allows phone use without participant signer access. Requires Enrollment V2 public-key authorization, explicit association with the exact encryption binding, device-local structured-clone permission, rotation/revocation and browser compatibility review. | **Profile, Enrollment V2 and browser-local key prerequisite implemented dormant; association lifecycle, runtime and admission remain disabled.** |
| Reviewed encryption-key challenge/response, potentially using the existing HPKE suite | Could demonstrate decryption/key-agreement possession for the exact encryption key. Requires a new authentication protocol, domain separation, challenge-oracle and cross-protocol analysis; existing HPKE message wrapping does not authorize it. | Requires an explicit change to the encryption-only key policy; not implemented. |
| Device-bound platform credential | Could provide request signatures with platform key protection. Must establish device-specific, non-synced ownership, browser support, exact enrollment and loss/rotation behavior; a generic synced credential does not prove this device. | Separate policy/protocol decision, not implemented. |

Participant signatures on every request prove participant control, not possession
of the exact messaging device, and cannot require phone NIP-07/NIP-46. Bearer
secrets, saved QR/exchange verifiers, caller-provided device IDs and server-held
device private keys are not options. The pure server contracts generate no key
material; only explicit use of the dormant browser prerequisite generates and
structured-clones the separate local key.

Approval must explicitly authorize the local key policy, Enrollment V2 and
binding association. The source implementation and fixed vectors select the
exact profile above. Both public keys must be approved in one exact association,
with proof of possession of the new authentication key at enrollment. This must
be a versioned extension, not a reinterpretation of existing signed binding
bytes or IDs. Every change to either key invalidates the association and
outstanding challenges. Existing devices require explicit enrollment; OAuth
cannot silently attach an auth key.
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

This digest is a content identity, not a credential or the signature preimage.
`tests/fixtures/social_messaging_device_admission_v1.json` freezes both complete
request/challenge wires, lengths and digests using independent Python standard
library canonicalization. They are contract vectors, not valid device proofs.

## Frozen canonical audience grammar

Request/challenge and Enrollment V2 audiences use the same grammar, identified
by `hodlxxi.canonical_https_origin.ascii_ldh_no_idn.v1` in the byte-identical
shared proof fixture's `audienceCorpus`. An audience is 1..255 ASCII bytes,
exactly `https://HOST` or `https://HOST:PORT`. Validation never normalizes input.

- DNS hosts are dot-separated labels of 1..63 lowercase ASCII letters, digits
  or hyphens; each label starts and ends with a letter or digit. Empty labels,
  trailing dots and underscores are forbidden. A final label consisting only
  of digits, or matching `0x[0-9a-f]*`, is forbidden unless the whole host is a
  canonical IPv4 address. This excludes alternative numeric URL-host forms.
  This narrow V1 grammar excludes IDNs, including every `xn--` label; it does
  not perform IDNA or punycode conversion.
- IPv4 is exactly four decimal octets in 0..255, with no leading zeros except
  the octet `0`. Abbreviated, integer, hexadecimal and octal forms are forbidden.
- IPv6 is bracketed, lowercase hexadecimal: no leading group zeros, and the
  longest run of at least two zero groups is compressed with `::`, choosing
  the first run on ties. A single zero group is never compressed. Zone IDs
  and dotted IPv4 tails are forbidden; mapped addresses use canonical hex.
- An optional port is decimal 1..65535, without leading zeros; explicit `443`
  is forbidden. No credentials, path, query, fragment, trailing slash,
  whitespace, percent encoding or Unicode is accepted. JSON-escaped Unicode
  is rejected after decoding as well as in constructors; canonical wire rules
  also reject alternate JSON escapes.

Social shares one audience validator between admission candidates and
Enrollment V2. UBID validates the host grammar explicitly and compares IPv4
and IPv6 against standard-library `ipaddress` canonical spelling. Every shared
corpus member is exercised through enrollment constructors/parsers and the
real request/challenge proof paths in both repositories. The fixture SHA-256
assertions pin the corpus alongside the unchanged signed vectors. These shape
checks do not authenticate an origin or grant final admission.

## Frozen proof wire, preimage and strict verification

The proof wire is compact lexically key-sorted printable-ASCII JSON with no
trailing newline and exactly:

```text
algorithm = Ed25519
challengeId = exact stored challenge ID, lowercase hex64
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
publicKey = exact approved Ed25519 key, lowercase hex64
schema = hodlxxi.social_messaging_device_proof.v1
signature = lowercase hex128
version = integer 1
```

The exact bytes signed are the ASCII bytes of compact lexically key-sorted JSON:

```text
challenge = exact immutable server-stored challenge STRING
domain = HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
publicKey = exact approved Ed25519 key
schema = hodlxxi.social_messaging_device_proof_preimage.v1
version = integer 1
```

Because the exact challenge embeds the exact request string, the signature binds
schema/version, operation, subject, session generation, accepted mobile/X25519
binding ID and version, device ID, method, path, body digest, recipient handle
where applicable, challenge ID, issue/expiry interval and audience. The proof
cannot carry challenge bytes; verification receives the immutable original from
the future challenge owner and compares the reconstructed actual request before
cryptography.

The current strict Ed25519 primitive implementation is in Social. It pins
`@noble/ed25519` 2.3.0, MIT, zero runtime dependencies, integrity
`sha512-M7dvXL2B92/M7dw9+gzuydL8qn/jiqNHaoR3Q+cb1q1GHV7uwE17WCyFMG+Y+TZb5izcaXk5TdJRrDUxHXL78A==`.
The verifier strictly decodes both public point A and signature point R with
ZIP-215 disabled, requires canonical byte-for-byte re-encoding, rejects identity
and small-order points, requires both points to be torsion-free, requires the
little-endian S scalar to be below the Ed25519 subgroup order, and then calls
Noble verification with `{zip215:false}`. Node supplies SHA-512 only; native
WebCrypto/OpenSSL Ed25519 verification is not used. The independent fixture pins
RFC 8032, the C2SP low-order/noncanonical/mixed-torsion corpus, the native
identity degeneracy and invalid S cases.

Successful pure verification returns separate states: canonical structure is
`valid`, strict cryptography is `valid`, current association is `not_evaluated`,
atomic challenge consumption is `not_implemented`, and final admission is
`denied`. UBID can reconstruct and validate the same canonical bytes, but reports
cryptography as `not_evaluated_by_ubid`; it is not a second cryptographic
authority.

## Frozen Enrollment V2 bytes

Enrollment V2 is compact lexically key-sorted printable-ASCII JSON, at most
4,096 bytes, with exactly:

```text
audience, deviceId, domain, ed25519PublicKey, enrollmentChallengeId,
expiresAt, issuedAt, profile, schema, subject, version, x25519BindingId,
x25519BindingVersion, x25519PublicKeyCommitment

domain = HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2
schema = hodlxxi.social_messaging_device_enrollment.v2
version = integer 2
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
```

The challenge is server-originated lowercase hex64. Timestamps are nonnegative
safe-integer epoch milliseconds with `issuedAt <= now < expiresAt` and a maximum
60,000-ms lifetime. The X25519 commitment is:

```text
"hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
hex(SHA256(ASCII("HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1")
|| NUL || lowercase-hex64-X25519-public-key))
```

The enrollment digest uses the same construction over the exact enrollment wire
with domain `HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2` and prefix
`hodlxxi-social-messaging-device-enrollment-v2-sha256:`.

Exactly one never-published kind-27236 external-signer event must have
`pubkey=session subject=enrollment subject`, `content=exact enrollment wire`,
`created_at=floor(issuedAt/1000)`, and ordered tags for purpose
`hodlxxi-social-messaging-device-enrollment-v2`, enrollment digest, challenge ID
and device ID. Social locally verifies its NIP-01 ID and BIP340 signature. The
existing one-shot signer boundary compares the provider key before `signEvent`
and releases the provider afterward. A different Full participant, OAuth-only
session, QR scan, operator or unsigned attachment cannot replace this event.

The phone proof wire contains exactly `algorithm`, `enrollmentChallengeId`,
`enrollmentDigest`, `profile`, `publicKey`, `schema`, `signature`, `version`, with
schema `hodlxxi.social_messaging_device_enrollment_proof.v2` and version 2. It
signs compact sorted JSON containing the exact enrollment wire, exact key and
profile under domain `HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2` and
schema `hodlxxi.social_messaging_device_enrollment_proof_preimage.v2`. It uses
the same strict Social verifier. Existing devices must re-enroll or re-pair.
Rotation/revocation must atomically invalidate the predecessor association and
all outstanding challenges; this increment defines but does not store that
lifecycle.

## Strict Social verification-statement producer

`src/server/messaging-device-verification-statement-v1.mjs` consumes UBID's
exact canonical verification context and input strings. The copied public
cross-repository fixture is
`tests/fixtures/social_device_admission_v1.json`, byte length 96,928 and SHA-256
`09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324`.
It is byte-identical to the fixture at UBID staging merge commit
`8e56b82643d4f6243140f046e8e6fab545185437`.

Both outer documents are closed, printable-ASCII, compact recursively
key-sorted JSON. Exact round trips reject duplicate, missing, unknown,
alternate-escaped, non-ASCII, unsafe-number, accessor, proxy, inherited, and
coercible representations. Embedded context, challenge, proof, approval event,
actual request, and routing request remain exact strings; digests cover their
original accepted bytes without normalization or reserialization. The context
and input digest domains and prefixes are exactly the UBID V1 contract.

For `enrollment-v2`, the producer calls the existing
`verifyEnrollmentV2Authorization` path. This performs real NIP-01 event-ID and
BIP340 signature verification, exact authenticated/enrollment subject matching,
exact Enrollment V2 audience/device/X25519/Ed25519/profile/challenge binding,
freshness, and strict Ed25519 phone proof of possession. For
`device-request-v1`, it calls the existing
`verifyMessagingDeviceProofV1` path, preserving the pinned Noble 2.3.0 strict
non-ZIP-215 point and scalar checks and the exact operation/session/device/
binding/audience/challenge/method/path/body commitment. No verifier or hash
implementation is injectable.

After and only after that verification succeeds, the producer creates this
exact closed protected header:

```json
{"alg":"RS256","kid":"<exact signer-bound identifier>","typ":"hodlxxi-social-device-verification+jws"}
```

The closed payload uses schema
`hodlxxi.social_device_verification_statement.v1`, version 1, and exactly
`attemptId`, `aud`, `challengeId`, `challengeKind`, `clientId`,
`contextDigest`, `expiresAt`, `inputDigest`, `iss`, `issuedAt`, `jti`,
`purpose`, `result`, `schema`, `servicePrincipal`, and `version`. Purpose is
fixed as `social_device_cryptographic_verification_v1`; result is fixed by the
challenge kind. Lifetime is a positive integer no greater than 10,000 ms,
expiry is exclusive with no skew, and the statement cannot outlive the
underlying proof challenge.

V1 derives its non-authority token identifier without ambient randomness:

```text
jti = hex(SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_VERIFICATION_STATEMENT_JTI_V1")
  || NUL
  || ASCII(canonical closed payload with jti omitted)
))
```

The signer is an opaque module-created infrastructure port bound to the exact
RS256 algorithm, protected-header key identifier, issuer, audience, client ID,
service principal, and purpose. Its signing operation is retained privately by
the module; the returned port exposes no callable method. The producer invokes
that operation only with its internally constructed compact-JWS signing input.
There is no generic signing export, key loader, public-key trust registry,
filesystem/environment read, network/database/socket/HTTP adapter, browser or
BFF integration, route, or runtime import.

The public producer is
`produceMessagingDeviceVerificationStatementV1(input, options)`. `input` is
closed over `contextWire`, `inputWire`, the five expected identity/purpose
values, `now`, `statementLifetimeMs`, and the opaque signer. The separate
construction gate requires the literal own-data option
`verificationStatementsEnabled: true`; its default is false. When disabled,
the producer fails before invoking the signer. No environment variable or
runtime factory can change that state in this increment.

A valid statement means only that Social cryptographic verification succeeded
for the two exact frozen byte strings at the stated time and purpose. It does
not mean current Full, current session or binding authority, challenge
consumption, device admission, message acceptance, routing authorization,
ciphertext persistence, or inbox access. Those remain exclusively future UBID
transactional decisions, and final admission remains denied.

## Required verifier interfaces and selected atomic owner

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
   reservation owned by that session, binding and the exact frozen profile.
   Caller JSON
   cannot replace it. Challenge expiry must also be bounded by session, Full,
   binding, accepted evidence and approved key-association deadlines.
3. `verifyInTransaction(exactChallengeWire, profileSpecificProof, lockedAuthority)`
   returns an immutable verified record with exactly `challengeDigest`,
   `proofProfile`, `sessionBinding`, `subject`, `deviceId`, `bindingId`,
   `bindingVersion`. Every field must match the reserved transcript and approved
   association, using the authority's public key, never a supplied replacement.
   A boolean, historical proof, digest, session, service credential or key
   equality is insufficient. The proof encoding is the frozen V1 wire above.
4. `resolveRecipientSelf(handle, lockedAuthority)` is required only for self-read
   and returns one exact confidential registry mapping as specified below.
5. `consumeAndApply(exactOperation)` rechecks time and current session/Full/
   lifecycle/evidence/key association after lock waits and verification, consumes
   the challenge exactly once and performs the authorized authority operation in
   the **same** transaction. Failures roll back without an outward grant. All
   calls must share this owner; detached verifiers and caller snapshots fail.

The future UBID atomic transaction must reuse the existing UBID Current-Full subject,
User, device, public-key and lifecycle lock domains or consume them through an
equally authoritative reviewed composition. Its complete lock order and
interaction with session/registry writers require review and race tests before
implementation. No independent Social cached Full decision may replace this,
and only the exact authenticated purpose-bound verification statement above may
transport Social's narrow cryptographic result.
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

Implement reviewed runtime integration for the dormant browser prerequisite,
supported-browser automation, session-generation binding, the UBID atomic
challenge/replay owner, authoritative association storage, authenticated
statement consumer/trust registration, rotation/revocation and lifecycle races.
Then implement confidential routing-registry
retention and recipient-self ownership, capability-bound package issuance,
minimized operation results and cross-owner lost-response/idempotency semantics.
Only then add Social ciphertext persistence, bounded inbox/cursors, quotas,
retention and sender-copy/history policy, default-off ingress/runtime wiring,
and complete offline lifecycle rehearsal. Phase 4 encryption/reception UI and
any activation remain separate. These prerequisite tests do not claim admission,
delivery, decryption or full messaging completion.
