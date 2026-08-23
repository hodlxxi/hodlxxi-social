# Authenticated Product Shell V1.18

V1.18 turns the ordinary authenticated Social entry into a usable responsive product workspace while preserving the existing authentication and authority boundaries.

## Product surfaces

- Home: current membership context, a visibly unavailable publishing boundary, an in-product guide and an explicit zero-event feed state.
- My Circle: the authenticated participant at the center of separate direct-friend and two-hop rings, with sponsor/covenant context kept distinct.
- People: Search, Discover, Friends and Friends of Friends with policy-safe zero-result states.
- Communication: Messages and Groups layouts with no claim of transport, encryption or delivery before those capabilities exist.
- Identity: Profile, Trust, Activity, Notifications and Settings based only on the authenticated subject and current external authority projection.
- Shell: desktop left navigation, centered workspace, right context rail and deliberate mobile bottom navigation.

## Data contract

The authenticated shell receives only:

- the canonical lowercase 64-hex subject from the opaque Social session;
- a formatter-valid current `limited` or `full` projection from the external HODLXXI authority boundary; or
- a fail-closed invalid Limited fallback.

The renderer creates no friend edge, sponsor edge, profile claim, public post, message, group, notification or engagement metric. Zero counts and empty states therefore describe the connected authenticated dataset rather than hiding missing integrations behind fixtures.

## Capability boundary

V1.18 adds no database, durable state, automatic relay selection, relay requirement, signing, publishing, message transport, custody or authority mutation. The disabled composer is presentation only. The separate synthetic demo and developer-only one-shot public-read surfaces remain isolated from the ordinary authenticated entry.

## Browser asset delivery

V1.19 assigns the same explicit revision to the authenticated stylesheet, module entry and its complete static import graph, including `authenticated-public-read.mjs` and `nostr-event-verifier.mjs`. This prevents a browser cache from combining the current HTML shell with an older renderer, verifier, navigation module or stylesheet. The offline production-readiness check requires the complete authenticated module graph; the revision is static release metadata and carries no subject, session, credential or authority information.
