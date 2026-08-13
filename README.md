# HODLXXI Social V1.7

An independent, Nostr-first social layer for the HODLXXI covenant trust network. Identity is a public key—not a username, password, KYC record, or application-issued label. V1 preserves the dependency-free V0.8 product shell while placing a strict normalized data/service boundary between the UI and its deterministic synthetic fixtures.

HODLXXI runtime/CRT remains the external authority for objective covenant status. Social consumes time-bounded assertions and falls back to Limited; it cannot grant Full or operator status. Social friendship and sponsor/covenant trust are separate relationships.

SyntheticSocialAdapter remains the active application adapter. V1.1 also implements an injectable `NostrPublicReadAdapter` boundary: an explicitly supplied read transport provides signed public kind `0` profiles and kind `1` notes, canonical Nostr mapping validates them, and only minimized Social records cross the service boundary. `READ_PUBLIC_NOSTR` is explicit, missing capabilities fail safely, and arbitrary relay JSON is never passed to rendering. No live relay is selected automatically.

V1.2 adds a separate `HodlxxiAuthorityReadAdapter`. Its only capability is `READ_EXTERNAL_AUTHORITY`, and its only transport seam is an injected `readAssertion(subject)` operation. The Social data service accepts social and authority adapters separately, passes authority responses through canonical V1 normalization, preserves valid Limited evidence, and projects every missing, failing, expired, malformed, unsupported, or mismatched assertion to Limited. Nostr data, friendship, sponsor trust, and local demo state cannot substitute for this authority source.

V1.3 adds a small deterministic composition root. `createComposedSocialDataService({ socialAdapter, authorityAdapter, now })` requires the caller to select the social source explicitly and keeps authority as a separate optional input. It delegates normalization and access projection to the existing Social data service; it does not merge adapter objects, discover sources, inspect environment or browser state, or become a source of truth. The application explicitly composes its deterministic synthetic source with the local fixture authority source. Valid authority provenance and evidence survive composition, while absent or invalid authority remains fail-closed at Limited without discarding usable social data.

V1.4 adds `WebSocketNostrReadTransport`, a dependency-free, explicitly constructed public-read transport. A caller must supply a validated `wss://` relay URL and may inject the WebSocket factory for its runtime. Each `read(filter)` opens one bounded socket, sends one Nostr `REQ`, collects only matching `EVENT` frames until `EOSE` or the configured event limit, sends `CLOSE`, and cleans up. Connection, read, message-size, accumulated-data, and event-count bounds prevent unbounded listening. Offline tests use a deterministic fake WebSocket; canonical validation in `src/nostr.mjs` remains authoritative for every returned event.

This transport is a controlled construction seam, not the application default. `SyntheticSocialAdapter` remains the active application adapter, no relay is selected automatically, and no connection occurs on page load. A live public read exists only when a caller explicitly constructs `WebSocketNostrReadTransport({ relayUrl })` and injects it into `NostrPublicReadAdapter.create({ transport, viewerId })`.

V1.5 adds a developer-only, one-shot public relay probe. It requires an explicit relay and supported kind on every invocation, applies conservative event and timeout bounds, passes returned events through `NostrPublicReadAdapter` and canonical Nostr validation, prints only bounded normalized diagnostics, and exits. It does not change the application adapter or UI.

V1.6 adds a separate developer-only browser entrypoint at `web/dev-live.html`. It starts idle and requires a developer to enter an explicit `wss://` relay for each page session. Each manual action performs one bounded read (3 events by default, at most 10, with 5-second open and read timeouts) through `WebSocketNostrReadTransport`, `NostrPublicReadAdapter`, the V1.3 composition root, and `SocialDataService`. Only normalized public notes are rendered, using text-only DOM fields. There is no synthetic fallback when a live read fails.

V1.7 adds a separate CLI-only, one-shot UBID current-entitlement probe. It requires an explicit canonical credential-free HTTPS origin and lowercase x-only subject, makes one bounded read, validates the exact `hodlxxi.current_entitlement_assertion.v1` response, and exits. It is not imported by either browser application or the Nostr probe, and tests inject transport without making live requests.

```text
node scripts/hodlxxi-authority-probe.mjs --origin https://authority.example --subject <lowercase-64-hex-public-key> --timeout-ms 5000
```

Successful output is only a current read-only assertion. It cannot issue status, authenticate key ownership, grant Operator, mutate covenant trust, or establish continuing availability. Exit codes are 2 for arguments, 3 for denied, 4 for unavailable, 5 for malformed, and 6 for invalid subject; a validated Limited or Full assertion exits 0.

V1.8 adds a developer-only one-shot Social projection of that assertion. The runtime remains the sole external authority: Social does not grant Full, but may reflect a validated, externally asserted, time-bounded Full after it crosses the existing authority adapter, normalization, composition root, and Social data service. Run it only with an explicit canonical credential-free HTTPS origin and explicit lowercase x-only subject:

```sh
node scripts/hodlxxi-authority-social-probe.mjs --origin https://authority.example --subject <lowercase-64-hex-public-key> --timeout-ms 5000
```

Its immutable `hodlxxi.social_authority_projection.v1` record contains, in order, only `schema`, `version`, `subject`, `assertedIdentityClass`, `valid`, `diagnostic`, `evidenceSource`, and `observedAt`. The asserted class is Limited or Full only; Operator is impossible in this source. Missing or invalid authority fails closed to invalid Limited. Selecting the subject is routing context, not authentication, proof of ownership, membership, trust, or control of the key. The CLI performs no writes, refresh, polling, persistence, or deployment, and a time-bounded assertion is not permanent status. The normal synthetic UI and Nostr-only development page remain unchanged; V1.8 is not a production mode.

The dev page labels `DEV / LIVE PUBLIC NOSTR DATA` separately from `DEMO VIEWER / AUTHORITY NOT LIVE`. Its local demo viewer is not authenticated, and Nostr data cannot provide HODLXXI membership, Full or Operator status, CRT validity, verified identity, sponsor trust, or covenant authority. Missing live authority remains fail-closed at Limited. The ordinary `web/index.html` application remains synthetic/offline and neither imports the live transport nor connects on load.

Run the manual probe after merge with a caller-selected public relay (the relay below is deliberately a placeholder):

```text
node scripts/nostr-relay-probe.mjs --relay <explicit-wss-relay> --kind <0-or-1> --limit 3 --timeout-ms 5000
```

Optional `--author <64-hex-public-key>` narrows the request further; `--json` selects sanitized JSON output. The event limit is 1–10 (default 3), and the timeout is 250–30000 milliseconds (default 5000). Exit codes are 2 for arguments or relay configuration, 3 for transport failure, 4 for timeout, 5 for malformed relay results, and 6 for canonical validation failure. A successful read with no events exits successfully with `zero-events`.

Implemented now: an explicit developer-only live public-feed preview, session-memory relay selection, bounded one-shot reads, the existing WebSocket transport, Nostr adapter, composition/service boundary and canonical validation pipeline, source-truth labeling, the V1.5 Nostr command-line probe, and the isolated V1.7 UBID current-entitlement command-line probe. The normal product remains synthetic/offline by default.

Not implemented: production live mode, automatic source or relay selection, relay discovery, relay pools, reconnect, persistent subscriptions, polling, personalized feeds, authentication, signing, publishing, DMs, encryption, NIP-07, application-integrated live HODLXXI authority, persistence, or deployment.

Successful probe output means “a public Nostr relay read succeeded and accepted events passed current validation.” It does not mean HODLXXI membership, Full or Operator status, CRT, identity ownership, relay trust, or content trust was verified.

Not implemented: default live mode, relay discovery, relay pools, reconnect, persistent subscriptions, publishing, signing, DMs, encryption, authentication, NIP-07, NIP-44, NIP-59, NIP-65, production relay selection, application-integrated HODLXXI runtime transport, environment-based configuration, private-key access, HODLXXI authentication, CRT issuance, covenant or chain validation, sponsor/status mutation, writes to HODLXXI, or production deployment. The current viewer remains explicitly injected local state and does not establish key ownership.

Open `web/index.html` through any static file server, then use the grouped desktop navigation or the mobile primary and More navigation for Home, Search, Discover, My Circle, Friends, Friends of Friends, Messages, Groups, Notifications, Activity, participant profiles, and Trust. Switch among synthetic participants to explore Limited, Full, and Operator views. The selector is a local demo control, not a login; viewer selection is in-memory only, recomputes route visibility, and cannot edit externally derived access status. Run `node --test` for deterministic Node built-in tests.

For an explicit manual development check after serving the worktree locally: open `web/dev-live.html`, enter a developer-selected public `wss://` relay, choose **Read once**, and confirm bounded accepted public notes or an explicit empty/failure state. Then open ordinary `web/index.html` and confirm it still shows the synthetic offline shell. This sequence is manual only; automated tests inject fake WebSockets and never access a relay.

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
- This repository contains no custody, signing, publishing, automatic or production relay selection, database, Redis, Bitcoin RPC, LND, or deployment integration.

See [architecture](docs/architecture.md), [domain/access](docs/domain-access-model.md), [Nostr boundary](docs/nostr-boundary.md), and [graph/visibility](docs/social-graph-visibility.md).
