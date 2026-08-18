# Production Readiness V1.16

V1.16 prepares HODLXXI Social for a later controlled deployment without performing that deployment.

The offline readiness command is: node scripts/hodlxxi-social-production-readiness.mjs

It validates the existing confidential OAuth/BFF configuration, required authenticated browser assets, distinct Social and authority origins, and emits only minimized non-secret readiness facts.

It starts no listener, performs no network request, exposes no OAuth secret, changes no DNS, nginx, systemd, OAuth registration, UBID runtime, covenant state, or production deployment.

GET /auth/health is liveness only and reads no session, authority assertion, OAuth token, public key, covenant state, or social data.

The intended future topology is static Social assets at the Social HTTPS origin with only /auth/* proxied to the loopback Social BFF. HODLXXI/CRT remains the external read-only authority source.
