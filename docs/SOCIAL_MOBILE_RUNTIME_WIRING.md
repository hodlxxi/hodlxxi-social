# Trusted mobile/session runtime wiring

This is server source composition only. The
[mobile consumer contract](SOCIAL_MOBILE_CONSUMER_PHASE2B.md) still governs
cookies, CSRF, exact viewer credentials, absolute pairing expiry and logout.
There is no database, deployment, provisioning, route activation or automatic
browser UI mount in this change.

## Future operator switches

`SOCIAL_UBID_SESSION_ISSUANCE_ENABLED` defaults false. When explicitly `true`,
the ordinary server CLI validates and constructs the existing issuance client
from these required settings:

| Environment setting | Validation / client input |
| --- | --- |
| `SOCIAL_UBID_SESSION_ISSUANCE_ISSUER_ORIGIN` | Canonical HTTPS origin, exactly `HODLXXI_AUTHORITY_ORIGIN`; `issuerOrigin` |
| `SOCIAL_UBID_SESSION_ISSUANCE_PRIVATE_SOCKET_PATH` | Canonical absolute Unix socket path, <=107 bytes; `socketPath` |
| `SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_ID` | Explicit existing issuance backend client ID, `[A-Za-z0-9._:-]{1,255}`; no default; `clientId` |
| `SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_CLIENT_SIGNING_KEY_ID` | Existing key ID, `[A-Za-z0-9._:-]{1,255}`; `clientSigningKeyId` |
| `SOCIAL_UBID_SESSION_ISSUANCE_SERVICE_SIGNING_KEY_PATH` | Canonical absolute path to existing server infrastructure RSA private key |
| `SOCIAL_UBID_SESSION_ISSUANCE_TIMEOUT_MS` | Integer 250–5000; `timeoutMs` |

No resource URL, audience, scope or purpose override is accepted by the client.
It derives the exact service-token audience and fixed issuance resource paths
from the issuer. Scope stays `social:session-issuance:manage`; UBID validates
purpose `social_session_issuance_v1`. Transport remains explicitly Unix-only,
with no DNS, TCP, proxy, redirect or ambient fetch fallback. Constructing the
client performs no request or socket access.

Issuance configuration alone leaves mobile composition disabled. A future
operator must also explicitly set `SOCIAL_MOBILE_ENABLED=true`, retain
an explicitly configured `HODLXXI_OAUTH_CLIENT_ID` matching the UBID lifecycle
client (`[A-Za-z0-9._:-]{1,255}`), and
supply the independently provisioned mobile client configuration:

- `SOCIAL_UBID_MOBILE_AUTHORIZATION_ISSUER_ORIGIN`
- `SOCIAL_UBID_MOBILE_AUTHORIZATION_PRIVATE_SOCKET_PATH`
- `SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_ID`
- `SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_CLIENT_SIGNING_KEY_ID`
- `SOCIAL_UBID_MOBILE_AUTHORIZATION_SERVICE_SIGNING_KEY_PATH`
- `SOCIAL_UBID_MOBILE_AUTHORIZATION_TIMEOUT_MS`

The mobile configuration follows the same origin, socket, identifier, key and
timeout validation. Its existing backend identity must be supplied explicitly;
this source does not invent or provision one or restrict it to an environment.
These identities are trusted server configuration, never browser/request input.
UBID's persisted issuer row remains authoritative for actual session issuance.
Missing or malformed enabled
configuration fails startup before the listener is created.

## Composition

`configFromEnvironment` parses trusted inputs without reading keys.
`createSocialMobileRuntime` loads enabled server keys as Node `KeyObject`s and
injects them into the two existing confidential clients. Files are opened with
`O_NOFOLLOW`, must be private regular files, and are read within a 16384-byte
bound. Keys must be RSA >=2048. No private key is exported, retained as a string
in configuration, returned to the browser or logged.

When mobile is off, the CLI keeps `createBoundedStore` and the old OAuth BFF.
When mobile is on, it uses the existing `createSessionStore`, calls
`createSocialMobileComposition({enabled:true,...})`, passes `mobilePostRoutes`
to `createHttpHandler`, and forwards `capabilitySessionReader` to the existing
recipient capability issuer/resolver. This retains current-authority resolution
on every mobile use, absolute expiry and cancellation-only logout retention.

`mountSocialMobileAuthorization` remains an independent explicit browser mount.
No browser entrypoint imports the server runtime or receives key material.
There is no browser service-token mint route. Any future browser mount and
operational activation require separate authorization; these switches are
documented here and are not executed or checked into environment files.

Focused tests: `node tests/social-mobile-runtime-config.test.mjs`, plus the
existing config, CLI, BFF and mobile composition unit test files. Test key
objects are synthetic, remain in memory and never use operational key paths.
