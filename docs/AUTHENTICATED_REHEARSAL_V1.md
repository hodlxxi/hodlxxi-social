# Authenticated Rehearsal V1.15

V1.15 provides a local-only end-to-end rehearsal for the ordinary authenticated HODLXXI Social product path.

It reuses the real V1.14 browser entry, OAuth BFF routing, PKCE transaction handling, opaque Secure/HttpOnly Social session, session-bound authority endpoint, Limited/Full projection, and logout path.

The rehearsal substitutes only the external dependencies:

- OAuth authorization is synthetic and local.
- The authenticated subject is a fixed synthetic lowercase x-only public key.
- Authority is explicitly synthetic Limited or Full.
- Operator is impossible.
- The listener binds only to loopback.
- TLS material is temporary and generated outside the repository.
- No production OAuth credentials are read.
- No request is sent to the HODLXXI production runtime.
- No DNS, nginx, systemd, OAuth registration, runtime, covenant, or production configuration is changed.

The rehearsal banner explicitly identifies synthetic identity and authority so its result cannot be confused with production authentication or real covenant status.

Automated tests exercise signed-out state, login redirect, authorization callback, opaque session creation, session-bound Limited/Full authority, caller-subject rejection, and logout. Manual browser rehearsal additionally verifies the ordinary product UI before and after authentication.

V1.15 is development verification infrastructure only. It is not a deployment mode and does not grant HODLXXI authority.
