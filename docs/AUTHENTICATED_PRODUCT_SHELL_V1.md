# Authenticated Product Shell V1.18

V1.18 turns the ordinary authenticated Social entry into a usable responsive product workspace while preserving the existing authentication and authority boundaries.

## Product surfaces

- Home: current membership context, a bounded public-note form gated by an exact-session external signer, an in-product guide and an explicit verified/empty feed state.
- My Circle: the authenticated participant at the center of separate direct-friend and two-hop rings, with sponsor/covenant context kept distinct.
- People: Search, Discover, Friends and Friends of Friends with policy-safe zero-result states.
- Communication: Messages and Groups layouts with no claim of transport, encryption or delivery before those capabilities exist.
- Identity: Profile includes a minimized public kind `0` editor; Trust, Activity, Notifications and Settings remain based only on the authenticated subject and current external authority projection.
- Shell: desktop left navigation, centered workspace, right context rail and deliberate mobile bottom navigation.

## Data contract

The authenticated shell receives only:

- the canonical lowercase 64-hex subject from the opaque Social session;
- a formatter-valid current `limited` or `full` projection from the external HODLXXI authority boundary; or
- a fail-closed invalid Limited fallback;
- minimized signature-verified public read state; and
- a non-secret publish relay host plus ephemeral signer/publication state.

The renderer fabricates no friend edge, sponsor edge, profile claim, public post, message, group, notification or engagement metric. Public profiles/posts render only after signature verification, and new public content enters the network only through the explicit external-signer sequence. Zero counts and empty states therefore describe the connected authenticated dataset rather than hiding missing integrations behind fixtures.

## Capability boundary

V1.20 permits only explicit external-signer kind `0` and kind `1` publication as defined in `AUTHENTICATED_PUBLIC_WRITE_V1.md`. Social does not hold key material, sign in application/server code, retain the signer, persist drafts/events, select a relay automatically, transport messages or mutate authority. Publishing controls remain disabled until an external NIP-07 key exactly matches the opaque authenticated session subject. The separate synthetic demo and developer-only one-shot surfaces remain isolated from the ordinary authenticated entry.

## Browser asset delivery

V1.20 assigns the same explicit revision to the authenticated stylesheet, module entry and its complete static import graph, including `authenticated-public-read.mjs`, `authenticated-public-write.mjs` and `nostr-event-verifier.mjs`. This prevents a browser cache from combining the current HTML shell with an older renderer, verifier, navigation module or stylesheet. The offline production-readiness check requires the complete authenticated module graph; the revision is static release metadata and carries no subject, session, credential or authority information.
