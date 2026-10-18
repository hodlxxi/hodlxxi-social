# Native V2 session bridge V1

This server-only source is default off and absent from the active server/BFF
import graph. It connects to UBID's distinct native session-issuance ingress,
not the V1 mobile contract. It does not adopt or relabel V1 credentials.

`createUbidSocialSessionV2Client` receives exact trusted HTTPS issuer identity,
a canonical absolute Unix socket, service client ID/key ID, an already-held
infrastructure RSA KeyObject and a bounded timeout. It has no key-file,
environment, DNS/TCP, proxy, cookie or redirect fallback. Each of offer, issue,
recover, resolve and revoke obtains a fresh independently scoped service token
using a real RS256 client assertion. Recovery forbids any viewer credential;
other methods keep service and original participant credentials in distinct
headers. Exact original protocol strings are preserved. The client performs
no automatic retry and sanitizes transport/provider failures.

The original V2 receipt has a HEX64 issuance ID, HEX64 issuance revision,
HEX64 acceptance ID and original whole-millisecond issued/expiry timestamps.
An active delivery requires the same original interval, a matching subject
and an independent child credential. V1 schemas, numeric revisions, ambiguous
JSON/HTTP headers, unknown fields and late delivery deny. Inactive retained
history contains null subject and credential. Transport shape validation is
not device cryptography, current Full evidence or admission.

`createNativeV2SessionStore` is the explicit opt-in wrapper around the bounded
session store. Ordinary existing stores still reject `ubid-mobile-v2`.
Native rows retain original issuance/acceptance provenance and absolute times,
with at most five minutes of cancellation-only retention. Expired rows never
authenticate. V1 record vocabulary and normal runtime construction remain
unchanged.

`createNativeV2SessionManager` installs only a closed genuine native delivery
whose subject, acceptance and maximum deadline match the trusted caller's
expectation. It resolves native authority freshly before installation and
every use, compares exact original receipt/provenance and checks asynchronous
cancellation/expiry before publishing an opaque presentation. Exact concurrent
retry returns the same original presentation without renewing TTL. In-flight
operations, aliases and storage are bounded. The public read/install result
contains no bearer. `capabilityRead` is private server composition state and
must never be serialized into a browser response.

Logout marks the retained slot locally denied before any await or capacity
check. Remote failure preserves that denial and permits exact original retry;
a confirmed retry performs no new remote work. An expired uninstalled original
can be cancelled through `cancelUninstalled`, which only revokes and never
installs or grants a session. The caller retains the exact original delivery
until installation is confirmed or cancellation acknowledged; this manager
does not supply durable recovery after a server restart. Lost or ambiguous
delivery must not trigger a new issuance or deadline.

Local tests use explicit HTTP stream and owner doubles, real ephemeral RSA
assertions and synthetic public clocks. They are not native socket/database
or browser proof. A separate private disposable PG16 test must prove the real
Node/Unix/Flask/native path with genuine time and verified teardown.

The existing browser/BFF, cross-device proposal/desktop approval, IndexedDB
upgrade and terminal cleanup, real Social statement producer and operational
factories/trust/routing remain separate work. No browser route is installed,
no participant private key is accepted or transmitted, no live service changes
and no device admission, Send or DM operation is enabled.

See [the enrollment client](SOCIAL_ENROLLMENT_V2_CLIENT_V1.md) and
[the canonical preacceptance handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md).
