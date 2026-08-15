# Social OAuth BFF V1 contract

This foundation makes Social a confidential HODLXXI OAuth client. Explicit runtime configuration supplies the two canonical HTTPS origins, client credentials, loopback listener, bounded timeouts, TTLs, and memory capacities. The callback is always derived as `<public-origin>/auth/callback`; it is not separately configurable. The secret is used only in server-to-server form bodies and never enters browser code, URLs, logs, errors, cookies, or documentation examples.

`GET /auth/login` creates independent random state, S256 PKCE verifier, and browser transaction identifier. A bounded one-shot record stores state and verifier, while a Secure, HttpOnly, SameSite=Lax, host-only cookie binds the browser. The authority redirect contains only the required authorization fields.

`GET /auth/callback` requires exactly one code, one state, and the matching transaction cookie. It consumes the record before one token request, never retries an ambiguous exchange, clears the transaction cookie for every terminal result, and immediately introspects the access token with confidential client authentication. Only an active lowercase 64-hex x-only subject is accepted. Tokens are then discarded and an unrelated opaque host-only Social session is created.

`GET /auth/session` returns a no-store allowlisted document: either `{ "authenticated": false }` or authentication plus the canonical subject. `POST /auth/logout` requires the exact Social Origin, deletes the session idempotently, expires its cookie, and performs no upstream operation. Security-sensitive cookies use exact cardinality and the supported unquoted RFC cookie-octet grammar; malformed input fails closed.

The HTTP adapter accepts no request body. Prohibited framing is rejected before routing without buffering. An exact bounded callback target still receives transaction-cookie deletion; near matches, malformed targets, and non-callback routes do not acquire OAuth-cookie behavior. Responses are bounded, sanitized, no-store, nosniff, and no-referrer.

All state is bounded, process-local, and non-durable. Restart logs users out. This version is suitable only for a controlled single process; multiple processes or horizontal scaling require a separately reviewed shared store. It adds no database or Redis.

OAuth authentication proves control of the canonical subject only. It does not grant Full or Operator status, current covenant authority, friendship, sponsorship, relay trust, custody, signing, or private-key access. NIP-07 selection remains routing and inspection context, not authentication. Future operation requires separately completed OAuth registration, secret provisioning, public HTTPS, exact proxy routing, TLS, and service supervision. None exists or is deployed by this patch, and the normal Social UI is not integrated with login.
