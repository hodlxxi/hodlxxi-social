# Production Readiness through V1.28B

The production-readiness command remains an offline, non-mutating validation:

`node scripts/hodlxxi-social-production-readiness.mjs`

It validates the existing confidential OAuth/BFF configuration, distinct Social
and external authority origins, separate explicit canonical `wss://` Nostr read
and publish relays, and the complete current authenticated browser asset graph.

Through V1.28B the required browser graph includes the viewer-private local
label store and the authenticated secure-messaging UX shell assets. Readiness
fails closed if those current production-facing assets are missing.

The report exposes only bounded, non-secret facts. It now distinguishes the
configured Full Directory mode, configured recipient-capability mode,
browser-device-local private-label source capability, and V1.28B
secure-messaging UI-shell source capability.

These are configuration/source facts, not deployment discovery. Asset presence
does not prove that a running process loaded that revision, and an enabled
configuration flag does not prove a successful authenticated production
transaction.

Readiness must not expose OAuth secrets, service assertions, bearer tokens,
cookies, private keys, signing-key paths, private socket paths, confidential
client identifiers, alias secrets, or participant identity mappings.

Readiness starts no listener, performs no network request, and changes no DNS,
nginx, systemd, environment, OAuth registration, UBID runtime, covenant state,
Full authority, Nostr state, browser persistence, or production deployment.

`GET /auth/health` remains liveness only. It reads no session, authority
assertion, OAuth token, participant public key, covenant state, Full Directory,
recipient capability, or Social graph data.

HODLXXI/CRT remains the external read-only authority. Full Directory
configuration and V1.27 recipient capabilities cannot create or elevate Full
authority. V1.28B readiness does not claim live encryption, device keys,
ciphertext transport, message storage, or direct messaging.

Repository CI currently uses Node 20. An older production Node major is a
separate deployment compatibility concern and must be changed through a
reviewed operations step rather than silently redefining this readiness
contract.
