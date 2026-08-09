# HODLXXI Social V1.3

An independent, Nostr-first social layer for the HODLXXI covenant trust network. Identity is a public key—not a username, password, KYC record, or application-issued label. V1 preserves the dependency-free V0.8 product shell while placing a strict normalized data/service boundary between the UI and its deterministic synthetic fixtures.

HODLXXI runtime/CRT remains the external authority for objective covenant status. Social consumes time-bounded assertions and falls back to Limited; it cannot grant Full or operator status. Social friendship and sponsor/covenant trust are separate relationships.

SyntheticSocialAdapter remains the active application adapter. V1.1 also implements an injectable `NostrPublicReadAdapter` boundary: an explicitly supplied read transport provides signed public kind `0` profiles and kind `1` notes, canonical Nostr mapping validates them, and only minimized Social records cross the service boundary. `READ_PUBLIC_NOSTR` is explicit, missing capabilities fail safely, and arbitrary relay JSON is never passed to rendering. No live relay is selected automatically.

V1.2 adds a separate `HodlxxiAuthorityReadAdapter`. Its only capability is `READ_EXTERNAL_AUTHORITY`, and its only transport seam is an injected `readAssertion(subject)` operation. The Social data service accepts social and authority adapters separately, passes authority responses through canonical V1 normalization, preserves valid Limited evidence, and projects every missing, failing, expired, malformed, unsupported, or mismatched assertion to Limited. Nostr data, friendship, sponsor trust, and local demo state cannot substitute for this authority source.

V1.3 adds a small deterministic composition root. `createComposedSocialDataService({ socialAdapter, authorityAdapter, now })` requires the caller to select the social source explicitly and keeps authority as a separate optional input. It delegates normalization and access projection to the existing Social data service; it does not merge adapter objects, discover sources, inspect environment or browser state, or become a source of truth. The application explicitly composes its deterministic synthetic source with the local fixture authority source. Valid authority provenance and evidence survive composition, while absent or invalid authority remains fail-closed at Limited without discarding usable social data.

Both read adapters are protocol seams, not production connectivity or authentication. Live relay selection, live HODLXXI runtime selection, environment-based configuration, authentication, signing, publishing, DMs, encryption, NIP-07, private-key access, HODLXXI authentication, CRT issuance, covenant or chain validation, sponsor/status mutation, writes to HODLXXI, production deployment, and automatic network connection are not implemented. The current viewer remains explicitly injected local state and does not establish key ownership.

Open `web/index.html` through any static file server, then use the grouped desktop navigation or the mobile primary and More navigation for Home, Search, Discover, My Circle, Friends, Friends of Friends, Messages, Groups, Notifications, Activity, participant profiles, and Trust. Switch among synthetic participants to explore Limited, Full, and Operator views. The selector is a local demo control, not a login; viewer selection is in-memory only, recomputes route visibility, and cannot edit externally derived access status. Run `node --test` for deterministic Node built-in tests.

Search matches only policy-permitted participants, visible posts, and accessible groups from local fixtures. Discovery offers deterministic local suggestions rather than personalized recommendations, live trends, or real-network popularity. Search history is not stored, denied identities do not contribute to result counts, and neither surface ranks or grants covenant trust or access status.

My Circle is a deterministic local SVG visualization: the current participant is centered, direct friends form the inner ring, and policy-permitted friends of friends form the outer ring. Generic restricted reach reveals no participant identity. Sponsor-trust is shown as a separate provenance overlay and never creates social reachability. Counts are synthetic fixture summaries, not live network statistics or trust scores.

Home includes a synthetic feed and an ephemeral local composer. Demo posts, reactions, and audience choices reset on reload and are never persisted, signed, sent, or published. `PUBLIC`, `FULL_NETWORK`, and `FRIENDS` are local presentation filters for this fixture shell; they are not cryptographic privacy guarantees or Nostr publication policy and never grant access status.

Messages and Groups are synthetic local product shells. Message history and locally added demo messages exist only in browser memory and reset on reload; they are not transported, delivered, persisted, signed, or encrypted. Groups are read-only presentation fixtures with no group authority or Nostr interoperability. Conversation and group membership never grants access status and is not evidence of friendship or sponsor/covenant trust.

Notifications and Activity are synthetic local summaries, not live network telemetry. Notification read state exists only in browser memory, resets on reload and viewer changes, and is never stored. Permitted notification targets reuse existing profile, message, and group access boundaries. Restricted activity is generic and exposes no denied participant identity or route. Reactions, messages, groups, and notification activity cannot change externally derived status or grant trust or operator authority.

## Safety and non-claims

- Friendship does not prove covenant trust.
- A displayed role or status is not legal identity.
- Social does not hold funds or control private keys.
- Participation does not promise profit or investment return.
- This repository contains no custody, signing, publishing, live relay selection, database, Redis, Bitcoin RPC, LND, or deployment integration.

See [architecture](docs/architecture.md), [domain/access](docs/domain-access-model.md), [Nostr boundary](docs/nostr-boundary.md), and [graph/visibility](docs/social-graph-visibility.md).
