# Dormant Social to UBID enrollment V2 client V1

This server-only client connects to the external UBID confidential enrollment
ingress contract. It is default off and is absent from the server startup,
runtime, BFF and browser import graphs. No route, session kind, database,
participant key, key-file lookup, environment setting or service is changed.

## Explicit transport and credentials

`createUbidSocialEnrollmentV2Client(config, dependencies)` returns `undefined`
when disabled. Enabled construction requires literal `enabled: true`, one exact
HTTPS issuer origin, a canonical absolute Unix socket path, backend client ID,
client signing key ID, an already held infrastructure RSA private KeyObject of
at least 2048 bits, and a bounded 250..30,000 millisecond operation timeout.
Configuration is copied, validated and frozen. Unknown fields, accessors,
proxies, alternate URLs, noncanonical paths and incomplete dependencies deny.

The infrastructure client key authenticates Social as a service; it is not a
participant/Nostr, Ed25519 device or X25519 encryption key. The client never
requests, imports, exports or stores a participant private key.

There is no DNS, TCP, public-origin fetch, cookie, proxy, redirect or credential
fallback. Requests use Node HTTP with only the configured `socketPath`, fixed
POST paths, explicit logical Host, no HTTP agent and bounded header/body sizes.
The injectable request/clock/random ports are trusted server test/composition
dependencies, never browser fields. The default clock is genuine `Date.now`;
one operation rejects backward movement.

| Method | Fixed path suffix | Exact body fields |
| --- | --- | --- |
| `challenge` | `/challenge` | `issuanceId` |
| `reserve` | `/reserve` | `issuanceId`, `verificationInputWire` |
| `finalize` | `/finalize` | `issuanceId`, `reservationId`, `reservationRevision`, `verificationInputWire`, `evidenceCompactJws`, `statementCompactJws` |

Each method accepts exactly `{body, viewerAccessToken}`. The prefix is
`/internal/v2/social/enrollment`; the token endpoint is its `/service-token`.
The caller must obtain the matching native V2 phone credential and immutable
issuance selector from trusted Social session state, not browser-supplied
identity. The wire revision is the exact string `"1"` required by UBID.
Nested input bytes remain exact canonical printable-ASCII strings.

Every operation generates a new 32-byte assertion JTI and a real RS256
private-key JWT using the existing confidential credential vocabulary. It posts
the assertion only to the fixed service-token audience. Requested scopes are
independently `social:enrollment-v2:challenge`, `:reserve` and `:finalize`.
The token response must have exactly the existing four fields, token type
Bearer, lifetime 60, the requested scope and an independent compact credential.
The participant bearer never accompanies the token request. The command uses
the service token in Authorization and the phone bearer only in
`X-HODLXXI-Viewer-Authorization`. Neither is placed in a URL or returned DTO.

## Bounded response and retry boundary

Every response must have status 200, one unambiguous JSON media type and content
length, `Cache-Control: no-store`, `Pragma: no-cache`, no encoding or chunked
transfer, a complete bounded stream and canonical duplicate-free JSON. The
publication envelope is closed and requires the command's exact schema,
version 1, committed publication, denied final admission and no bearer authority.

Challenge response strings are kept byte-identical and checked for original
context/enrollment/device/key/binding/approval-subject relationships, native
revision 1 and the same original exclusive interval. Reservation returns opaque
evidence and original reservation ID/times. Finalization compares the retained
receipt's original reservation, acceptance, association and challenge against
the exact request, and requires a literal boolean historical-recovery flag.
A historical receipt may be old; it never becomes current admission.

These checks are transport/publication checks, not a second implementation of
UBID's native authority or signed evidence consumer. The opaque RSA evidence
and receipt are not promoted to cryptographic/current authority by this client.
In particular, do not derive trusted producer configuration or current Full
status from these public objects. The unchanged real Social BIP340/Ed25519
verifier and dedicated statement producer remain separate prerequisites before
finalization; UBID independently verifies all signatures and current native
facts or exact accepted history.

Timeout, partial delivery, late exclusive expiry, wrong scope, malformed body,
provisional success and any provider error produce one non-sensitive failure.
The client destroys only the failing request/response and performs no retry.
An upstream commit may already exist despite failed delivery. A trusted caller
must retain the exact original artifacts and explicitly retry the same command;
it must not acquire a new challenge or renew a signed interval. Service-token
assertions are fresh per transport attempt, not renewal of enrollment evidence.

## Verification and remaining composition

Offline client tests use real RS256 assertions and an explicit in-process HTTP
stream double, with no listener or live socket. Adjacent V2 contract tests
retain the existing real BIP340 signatures and public fixed vectors.

A separate cross-repository test runner connects the actual Node client over
bounded stdio messages to the actual Flask test client, service assertion/token
crypto and real challenge/reservation/finalization owners. SQLite contains only
synthetic data; PostgreSQL catalogs, locks, challenge revision/native effects
and replay storage are explicitly doubled. The fixture's clock is not evidence
of genuine native acceptance performance. The runner never installs packages,
changes source, uses a real network transport or contacts a live database.

Separate disposable PostgreSQL rehearsals exercise the native restricted roles,
challenge revision trigger, concurrent creation and assertion replay, and the
complete genuine-clock commit/history flow. Another rehearsal runs this client
with its default HTTP, time and entropy ports over a real temporary Unix
listener into Flask and the real PostgreSQL owners. Wrong viewers, wrong
issuance and damaged signatures deny. Finalization writes one set of effects;
exact retry returns byte-identical receipt bytes without new effects. No
PostgreSQL catalog, lock, trigger, effect or replay storage is doubled there.

The native fixture trusts a synthetic Social RSA statement and uses a shape-only
phone proof. It is not new Ed25519 execution through this client or a deployed
browser flow. Real Social producer/UBID consumer cryptographic interoperability
remains separate evidence. Temporary listeners/processes/clusters are removed.

Before runtime/UI activation, operational composition must provide the native V2 session issuance/phone-session
bridge, server-selected verification producer profile and dedicated trust,
explicit restricted factories/Unix routing and the browser/BFF lifecycle. The
existing `ubid-mobile-v1` presentation is not silently upgraded into native V2.
The client does not sign or assemble a new Social verification statement, add
a native issuance endpoint, install a BFF route, admit a device or enable DMs.

Canonical Social crypto remains in
[the preacceptance handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md) and
[the exact admission contract](EXACT_MESSAGING_DEVICE_ADMISSION_V1.md).
