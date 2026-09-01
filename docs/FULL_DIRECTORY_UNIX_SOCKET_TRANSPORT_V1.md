# Full Directory Unix socket transport V1 (source only)

This change adds the disabled-by-default private transport needed by the existing Social Full-directory BFF. It changes source, tests, and documentation only. It does not configure a socket, provision a credential or signing key, edit nginx or systemd, restart a service, contact UBID, deploy, or activate Full Directory.

## Boundary and threat model

The production-intended dependency path is:

```text
browser
  -> same-origin Social BFF
  -> Social Unix-socket HTTP transport
  -> private nginx Unix socket
  -> UBID loopback gunicorn
```

The transport prevents the confidential service assertion and both request-scoped bearers from being routed through DNS, an IP address, ordinary loopback TCP, a public UBID URL, an environment proxy, or ambient `fetch`. It accepts only exact POST `/internal/v1/social/service-token` and GET `/internal/v1/social/full-directory` operations. Queries, fragments, redirects, alternate methods or paths, URL credentials, caller-supplied Host values, and every other destination fail closed.

Connection errors, refusal, aborts, timeouts, malformed responses, and validation failures collapse into the existing generic unavailable result. The socket path, private key, assertion, JTI, service bearer, human bearer, upstream exception, and participant population never enter logs or the browser response. Existing content-type, byte-size, UTF-8, duplicate-member JSON, exact schema, and alias-only response validation remains unchanged and authoritative.

## Logical HTTPS identities and physical transport

`SOCIAL_UBID_SERVICE_TOKEN_URL` and `SOCIAL_UBID_FULL_DIRECTORY_URL` remain canonical HTTPS logical endpoint identities. The transport derives only their exact request path and logical HTTP `Host`; it never resolves or connects to either hostname. `SOCIAL_UBID_SERVICE_TOKEN_ENDPOINT_AUDIENCE` remains a separate exact JWT audience and is not a network destination.

The physical destination is only the canonical absolute path in `SOCIAL_UBID_PRIVATE_SOCKET_PATH`. The Node-core HTTP request receives `socketPath` and no hostname, IP address, port, HTTPS agent, proxy, or fallback transport. No external runtime dependency is used.

## Authority remains independent

Unix-socket access grants network reachability only. A directory response still requires all three independent layers:

1. Social confidential service authentication and exact `social:full-directory:read` scope.
2. The canonical human OAuth viewer bearer retained only in the opaque server-side Social session.
3. Current UBID/CRT Full entitlement independently validated for that viewer.

The service credential is neither a human identity nor Full authority. Social does not grant Full, and the socket does not bypass UBID authorization.

## Configuration and activation prerequisites

Full Directory remains disabled unless `SOCIAL_FULL_DIRECTORY_ENABLED=true`. Disabled configuration keeps the exact `{ enabled: false }` shape and performs no socket parsing, inspection, transport creation, key loading, or UBID request.

When enabled, `SOCIAL_UBID_PRIVATE_SOCKET_PATH` is mandatory. Social accepts only a bounded canonical absolute Linux filesystem path: no root-only path, relative path, traversal, redundant separator, trailing separator, control character, whitespace, or non-canonical representation. An invalid or incomplete configuration retains the fixed non-secret startup diagnostic.

Production activation remains a separate reviewed operation requiring a private nginx Unix socket and UBID loopback upstream, restrictive socket ownership/mode, the confidential client registration and JWKS, a protected RSA signing-key file, complete Social environment configuration, deployment/restart approval, and post-activation fail-closed verification. Node cannot apply an `O_NOFOLLOW`-style flag atomically to a Unix-socket connect, so the configured socket and every parent directory must also be deployment-controlled, non-attacker-writable, and verified not to redirect through symlinks.
