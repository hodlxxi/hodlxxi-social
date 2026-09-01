# Full Directory BFF V1 (source only)

V1.24 adds a disabled-by-default Social backend-for-frontend path for the UBID privacy-safe Full directory. This is source code only: it does not activate the feature, provision credentials, alter production configuration, restart a service, or deploy anything.

## Authority separation

The Social backend is a confidential service client, not a Full user. Its service credential authenticates the Social workload only and does not establish human identity or Full authority. The canonical human OAuth bearer remains independently bound to the existing opaque Social session, while the existing HODLXXI authority projection must independently accept `status == "full"` and `valid == true` for that exact session subject. UBID remains canonical for the viewer's current Full authority.

The browser calls only same-origin `GET /auth/full-directory`. For each accepted call, the backend obtains one short-lived service bearer with exact scope `social:full-directory:read`, then sends the credentials separately:

```text
Authorization: Bearer <service bearer>
X-HODLXXI-Viewer-Authorization: Bearer <human OAuth bearer>
```

The human bearer remains only in the bounded process-local session record. `/auth/session` still returns only authentication state and canonical subject. Logout, session expiry, process restart, or normal session destruction removes the retained bearer. Neither credential, the client assertion, nor its JTI is logged or returned to browser code.

## Confidential client

The service client creates a fresh one-shot RS256 assertion with the configured client signing-key `kid`. Its `iss` and `sub` both equal the configured client ID, while `aud` is the exact configured token-endpoint audience string. The assertion has fixed UBID protocol claims `token_use=client_assertion`, `grant_type=client_credentials`, and `purpose=service_client_authentication`, plus a fresh JTI and a 60-second lifetime. The UBID service principal and UBID-issued service-token issuer are not client-assertion claims.

The RSA service-authentication key is loaded only from an explicit absolute server-side path. On the production Linux model, Social opens the final component with `O_NOFOLLOW`, requires a regular file, rejects every group/other permission bit, bounds the actual read to 32 KiB, and requires an RSA private key of at least 2048 bits. Source contains no private key, default key, generated production key, service secret, or production endpoint value. This key authenticates the Social service; it is not a participant identity key, a Nostr signing key, key custody, or Full authority.

Service-token and directory requests use separate bounded timeouts, strict status/content-type/size/JSON handling, no redirects, no retry, no caching, and no stale token or directory fallback. The service bearer exists only for the request flow.

The production-intended request implementation is the dependency-free [Full Directory Unix socket transport V1](FULL_DIRECTORY_UNIX_SOCKET_TRANSPORT_V1.md). Canonical HTTPS URLs remain exact logical endpoint identities, but the active server composition derives only their path and logical Host and connects solely through the configured Unix socket. There is no DNS, TCP, public-URL, proxy, HTTPS-agent, or ambient-fetch fallback.

## Privacy response contract

The accepted UBID document has exactly `schema`, `version`, and `participants`. Each participant has exactly `alias`, `identity_class`, and `current_full_relation_satisfied`; exact schema `hodlxxi.privacy_safe_full_directory.v1`, version `1`, `identity_class == "full"`, and `current_full_relation_satisfied == true` are required. Social immediately minimizes accepted entries to opaque pairwise aliases.

Unexpected fields or identity-, contact-, graph-, or wallet-like values fail closed. Social does not expose, cache, persist, infer, or reconstruct raw participant keys, subjects, XPUBs, descriptors, addresses, UTXOs, Nostr keys, X25519 keys, email, phone, sponsor/covenant graph data, or identity-resolution mappings. Pairwise aliases are presentation identifiers only; they are not names, profiles, global identifiers, or authority.

Denial, disabled configuration, missing authority, malformed data, or upstream unavailability returns one no-store `{ "state": "unavailable" }` response without participant data or population count.

## Disabled configuration contract

`SOCIAL_FULL_DIRECTORY_ENABLED` defaults to disabled. Enabling requires all of the following, with no defaults for private integration values:

- `SOCIAL_UBID_SERVICE_TOKEN_URL`
- `SOCIAL_UBID_FULL_DIRECTORY_URL`
- `SOCIAL_UBID_PRIVATE_SOCKET_PATH`
- `SOCIAL_UBID_SERVICE_CLIENT_ID`
- `SOCIAL_UBID_SERVICE_CLIENT_SIGNING_KEY_ID`
- `SOCIAL_UBID_SERVICE_TOKEN_ENDPOINT_AUDIENCE`
- `SOCIAL_UBID_SERVICE_SIGNING_KEY_PATH`
- `SOCIAL_UBID_SERVICE_TOKEN_TIMEOUT_MS`
- `SOCIAL_UBID_FULL_DIRECTORY_TIMEOUT_MS`

The two URLs are canonical HTTPS logical identities, not TCP destinations. The token-endpoint audience is an exact credential string and may be HTTPS or opaque/URN-style; it is not derived from the service-token HTTP URL. The private socket path must be a bounded canonical absolute Linux path. Incomplete or unsafe enabled configuration fails startup closed. The configured `kid` must select exactly one matching RSA public JWK in UBID. Node's portable file API cannot atomically prohibit symlinks in every signing-key parent component, so trusted non-symlink parent directories and deployment ownership remain activation prerequisites.

## Still not implemented or activated

- Production socket/nginx wiring, configuration, credentials, key provisioning, deployment, activation, or service restart.
- Browser access to UBID internal endpoints or a public identity-resolution endpoint.
- Names, profiles, avatars, presence, graph edges, messaging, or contact information.
- Protected content transport, encryption, X25519, payments, or Nostr membership publication.
- Durable/shared session storage or directory persistence.
