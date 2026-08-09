# HODLXXI Social V0.6

An independent, Nostr-first social layer for the HODLXXI covenant trust network. Identity is a public key—not a username, password, KYC record, or application-issued label. V0.6 is a dependency-free, multi-surface product shell that works offline with synthetic fixtures.

HODLXXI runtime/CRT remains the external authority for objective covenant status. Social consumes time-bounded assertions and falls back to Limited; it cannot grant Full or operator status. Social friendship and sponsor/covenant trust are separate relationships.

Open `web/index.html` through any static file server, then use the local hash navigation for Home, My Circle, Friends, Friends of Friends, Messages, Groups, Notifications, Activity, participant profiles, and Trust. Switch among synthetic participants to explore Limited, Full, and Operator views. Viewer selection is in-memory only, recomputes route visibility, and cannot edit externally derived access status. Run `npm test` for deterministic Node built-in tests.

My Circle is a deterministic local SVG visualization: the current participant is centered, direct friends form the inner ring, and policy-permitted friends of friends form the outer ring. Generic restricted reach reveals no participant identity. Sponsor-trust is shown as a separate provenance overlay and never creates social reachability. Counts are synthetic fixture summaries, not live network statistics or trust scores.

Home includes a synthetic feed and an ephemeral local composer. Demo posts, reactions, and audience choices reset on reload and are never persisted, signed, sent, or published. `PUBLIC`, `FULL_NETWORK`, and `FRIENDS` are local presentation filters for this fixture shell; they are not cryptographic privacy guarantees or Nostr publication policy and never grant access status.

Messages and Groups are synthetic local product shells. Message history and locally added demo messages exist only in browser memory and reset on reload; they are not transported, delivered, persisted, signed, or encrypted. Groups are read-only presentation fixtures with no group authority or Nostr interoperability. Conversation and group membership never grants access status and is not evidence of friendship or sponsor/covenant trust.

Notifications and Activity are synthetic local summaries, not live network telemetry. Notification read state exists only in browser memory, resets on reload and viewer changes, and is never stored. Permitted notification targets reuse existing profile, message, and group access boundaries. Restricted activity is generic and exposes no denied participant identity or route. Reactions, messages, groups, and notification activity cannot change externally derived status or grant trust or operator authority.

## Safety and non-claims

- Friendship does not prove covenant trust.
- A displayed role or status is not legal identity.
- Social does not hold funds or control private keys.
- Participation does not promise profit or investment return.
- This repository contains no custody, signing, live relay, database, Redis, Bitcoin RPC, LND, or deployment integration.

See [architecture](docs/architecture.md), [domain/access](docs/domain-access-model.md), [Nostr boundary](docs/nostr-boundary.md), and [graph/visibility](docs/social-graph-visibility.md).
