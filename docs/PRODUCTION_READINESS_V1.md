# Production Readiness through V1.20

V1.16 prepares HODLXXI Social for a later controlled deployment without performing that deployment.

The offline readiness command is: node scripts/hodlxxi-social-production-readiness.mjs

It validates the confidential OAuth/BFF configuration, separate explicit canonical `wss://` Nostr read and publish relays, the complete revisioned authenticated browser graph, distinct Social and authority origins, and emits only minimized non-secret readiness facts.

It starts no listener, performs no network request, exposes no OAuth secret, changes no DNS, nginx, systemd, OAuth registration, UBID runtime, covenant state, or production deployment.

GET /auth/health is liveness only and reads no session, authority assertion, OAuth token, public key, covenant state, or social data.

The topology is static Social assets at the Social HTTPS origin with `/auth/*` proxied to the loopback Social BFF. HODLXXI/CRT remains the external read-only authority source. After session validation, the browser may receive separate non-secret public read and publish relay URLs and connects directly. The BFF never proxies Nostr events, resolves a signer, receives private-key material or performs a HODLXXI write. Readiness itself still performs no network request or write.
