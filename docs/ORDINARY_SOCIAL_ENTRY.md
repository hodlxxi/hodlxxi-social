# Ordinary Social entry with mobile authorization enabled

The ordinary Sign in button first reads the non-secret, uncached
`GET /auth/entry-config` response. When the composed BFF requires a mobile
context, the browser prepares it using the existing same-origin JSON context
route with exactly `{"purpose":"login"}`, then navigates to `/auth/login`.
The context alone grants no session or entitlement. OAuth state, PKCE,
transaction binding, authority validation and the existing callback fence
remain required. No console command or external signer is requested by this
entry helper.

An explicit new login can replace an abandoned ordinary OAuth context.
It cannot replace a retained authenticated session, pending logout, phone
pairing, issuance or orphaned credential. Replacing a context invalidates its
previous callback fence. The original empty context body remains supported
for existing mobile callers.

For Sign out, `{"purpose":"logout"}` obtains the context's CSRF value,
including for a previously denied context awaiting logout confirmation.
The browser sends that value with the existing JSON logout request. Pending
logout stays denied and is reported as unconfirmed; a retry can complete it,
including after a page reload. A fresh login is permitted after confirmed or
local-only completion, subject to the retained-session checks.

The non-mobile composition still uses ordinary OAuth and its existing logout
contract. Entry configuration failure never causes fallback to an unguarded
flow. Each preparatory request has a five-second abort deadline and a 1 KiB
response limit. Public errors contain no upstream diagnostic or credentials.

Deploy the frontend and BFF together. The new browser module must be included
in the nginx static-file allowlist and served with the existing module MIME
policy; updating JavaScript alone is insufficient. The entry script URL has
a new cache key. No feature flag, issuer, client registration, certificate,
database, migration or deployment configuration is changed by this patch.

This correction does not grant Full, activate dormant messaging, implement
the missing message transport/composer, or fix UBID's separate logout page.
Full entitlement and real participant acceptance still require UBID authority
and subsequent browser checks against the selected staging issuer.

Tests in `tests/social-ordinary-entry.test.mjs` exercise the real BFF/mobile
composition and frontend helper with synthetic OAuth and upstream clients.
They cover ordinary entry in both modes, cancellation/retry, stale contexts,
logout/retry, QR preservation, CSRF/origin rejection, bounded requests and the
real button binding. They do not claim a real browser login or deployment.

## Explicit directory recovery

Full Network and Messages show a Retry directory button after a directory
failure. It issues one same-origin request, only for the current authenticated
Full viewer on those routes. Duplicate clicks cannot create overlapping
requests. The existing server-side authority and viewer checks and browser
response validation are unchanged. No successful list is fabricated or
reused to hide a failure, and there is no background retry loop.

Directory fetches now have a ten-second abort deadline. Logout aborts a pending
fetch; a late result cannot restore a signed-out viewer's directory. Failed
requests restore the retry action. This removes the need to reload the whole
page after a transient directory failure; it does not establish the original
cause of an intermittent upstream failure.

The browser entry and product-module cache keys are updated together. Public
Nostr read/write and event-verification modules, signer connection and post
publication handlers are unchanged. Tests also cover directory recovery
followed by explicit signer connection and post publication using synthetic
dependencies. Real relay acceptance remains a browser acceptance check.
