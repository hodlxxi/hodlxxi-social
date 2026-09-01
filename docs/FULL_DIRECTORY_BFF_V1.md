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

The service client creates a fresh one-shot RS256 assertion with configured issuer, principal/subject, audience, purpose, and token-use claims, a fresh JTI, and a 60-second lifetime. Its RSA service-authentication key is loaded only from an explicit absolute server-side path. Source contains no private key, default key, generated production key, service secret, or production endpoint value. This key authenticates the Social service; it is not a participant identity key, a Nostr signing key, key custody, or Full authority.

Service-token and directory requests use separate bounded timeouts, strict status/content-type/size/JSON handling, no redirects, no retry, no caching, and no stale token or directory fallback. The service bearer exists only for the request flow.

## Privacy response contract

The accepted UBID document has exactly `schema`, `version`, and `participants`. Each participant has exactly `alias`, `identity_class`, and `current_full_relation_satisfied`; the configured schema/version, `identity_class == "full"`, and `current_full_relation_satisfied == true` are required. Social immediately minimizes accepted entries to opaque pairwise aliases.

Unexpected fields or identity-, contact-, graph-, or wallet-like values fail closed. Social does not expose, cache, persist, infer, or reconstruct raw participant keys, subjects, XPUBs, descriptors, addresses, UTXOs, Nostr keys, X25519 keys, email, phone, sponsor/covenant graph data, or identity-resolution mappings. Pairwise aliases are presentation identifiers only; they are not names, profiles, global identifiers, or authority.

Denial, disabled configuration, missing authority, malformed data, or upstream unavailability returns one no-store `{ "state": "unavailable" }` response without participant data or population count.

## Disabled configuration contract

`SOCIAL_FULL_DIRECTORY_ENABLED` defaults to disabled. Enabling requires all of the following, with no defaults for private integration values:

- `SOCIAL_UBID_SERVICE_TOKEN_URL`
- `SOCIAL_UBID_FULL_DIRECTORY_URL`
- `SOCIAL_UBID_SERVICE_CLIENT_ID`
- `SOCIAL_UBID_SERVICE_PRINCIPAL`
- `SOCIAL_UBID_SERVICE_ISSUER`
- `SOCIAL_UBID_SERVICE_AUDIENCE`
- `SOCIAL_UBID_SERVICE_ASSERTION_PURPOSE`
- `SOCIAL_UBID_SERVICE_ASSERTION_TOKEN_USE`
- `SOCIAL_UBID_SERVICE_SIGNING_KEY_PATH`
- `SOCIAL_UBID_FULL_DIRECTORY_SCHEMA`
- `SOCIAL_UBID_FULL_DIRECTORY_VERSION`
- `SOCIAL_UBID_SERVICE_TOKEN_TIMEOUT_MS`
- `SOCIAL_UBID_FULL_DIRECTORY_TIMEOUT_MS`

Incomplete or unsafe enabled configuration fails startup closed. The exact activation values must be verified against the deployed UBID contract and provisioned outside source.

## Still not implemented or activated

- Production configuration, credentials, key provisioning, deployment, or service restart.
- Browser access to UBID internal endpoints or a public identity-resolution endpoint.
- Names, profiles, avatars, presence, graph edges, messaging, or contact information.
- Protected content transport, encryption, X25519, payments, or Nostr membership publication.
- Durable/shared session storage or directory persistence.
