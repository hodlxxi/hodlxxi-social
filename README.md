# HODLXXI Social V1.18

An independent, Nostr-first social layer for the HODLXXI covenant trust network. Identity is a public key—not a username, password, KYC record, or application-issued label. V1 preserves the dependency-free V0.8 product shell while placing a strict normalized data/service boundary between the UI and its deterministic synthetic fixtures.

V1.18 replaces the ordinary authenticated entry's technical placeholders with the first production-facing product shell from the UX blueprint. Home now presents a current membership chip, read-only composer boundary, product guide and honest feed state; Profile, My Circle, Search, Discover, Friends, Friends of Friends, Messages, Groups, Notifications, Activity, Trust and Settings are complete responsive surfaces rather than blank route notices. Only the session public key and current external Limited/Full projection enter the shell. No participant, relationship, post, message, group or activity is fabricated to fill an empty network.

V1.18.1 pins one shared browser asset revision on the authenticated stylesheet, module entry and its static import graph. A deployment can therefore never combine a new `index.html` with an older cached product renderer or stylesheet. Production readiness also requires every module in that authenticated entry graph, including `auth-product.mjs`, before reporting ready.

V1.15 adds a local-only authenticated browser rehearsal. It exercises the real V1.14 product entry, OAuth BFF transaction/session path, session-bound Limited/Full authority projection, and logout while replacing external OAuth and authority with unmistakably synthetic loopback-only inputs. The rehearsal makes no production HODLXXI request, uses no production OAuth credential, changes no deployment configuration, and cannot grant real Full or Operator authority.

V1.16 adds code-only production-readiness verification without deploying Social. It adds a minimal unauthenticated `GET /auth/health` endpoint and an offline readiness command that validates the existing confidential OAuth configuration, requires separate Social and external authority origins, verifies required browser assets, reports only non-secret deployment facts, and starts no listener or network request. Production OAuth registration, credential provisioning, DNS, TLS termination, nginx, systemd, and live deployment remain separate work.

V1.13 adds an offline-tested, explicit opt-in confidential OAuth backend-for-frontend foundation. The ordinary browser UI remains static and contains no secret. Only explicit invocation of the server-side BFF entrypoint reads validated configuration and OAuth client credentials; secrets stay server-side, are never browser imports, and no secret is checked into this repository. Importing a server module starts no service.

The BFF starts Authorization Code transactions with S256 PKCE and binds one-shot state to a separate opaque browser transaction cookie. After a single server-side code exchange it authenticates the token through client-authenticated introspection and creates an opaque host-only Social session. `GET /auth/session` exposes only authentication state and the canonical subject; same-origin `POST /auth/logout` deletes that process-local session.

V1.14 connects the confidential OAuth BFF to the ordinary Social UI in code, but nothing is deployed. No production OAuth client registration, secret provisioning, DNS, TLS, proxy, systemd service, or live production login is performed here. Sessions remain bounded, process-local, and non-durable. OAuth authentication proves only the canonical public-key subject; it does not grant Full or Operator status, friendship, covenant or sponsor authority, or relay authority. NIP-07 remains separate development routing context and is not an authenticated Social session.

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

V1.9 adds a separate developer-only browser entrypoint at `web/dev-authority.html`. It starts idle and requires an explicit canonical credential-free HTTPS origin, lowercase 64-character x-only subject, and timeout from 250 through 30000 milliseconds. Each accepted manual submission runs the unchanged V1.8 Social authority composition exactly once and displays only its formatter-valid projection or a visible fail-closed Limited result. The validated subject remains visible while loading and after authority failures; unvalidated input is not presented as a selected subject. Evidence containing `operator` in any casing is suppressed as display text without changing an otherwise valid Limited or Full assertion.

V1.10 adds the separate developer-only `web/dev-participant.html` preview. One deliberate accepted submission uses one validated public key for one existing HODLXXI authority composition, one subject-scoped public Nostr profile lookup, and one subject-scoped bounded public-note lookup. The page starts idle, keeps authority and Nostr failures independent, renders only normalized public data with text DOM operations, and has no retry, polling, persistence, source discovery, synthetic fallback, signing, publishing, or writes. Subject selection is routing context only, not authentication, ownership proof, legal identity, trust, or permanent membership; valid external Full or Limited remains solely runtime-asserted and every invalid authority outcome fails closed to Limited.

V1.11 adds the separate developer-only `web/dev-participant-shell.html` product view. After one accepted explicit submission it maps only the V1.10 validated result into one immutable, read-only Social snapshot and renders the selected participant and bounded public notes through the existing profile, badge, feed, page, and navigation presentation boundaries. The ordinary synthetic application now starts through an explicit page marker; importing its pure renderers from the developer shell does not start fixtures or perform live reads.

V1.12 adds an optional developer-only NIP-07 public-key selector to that page. Only a deliberate **Select key from NIP-07 extension** click resolves the injected local provider and calls `getPublicKey()` once. A strictly validated lowercase 64-hex result is extension-selected public-key routing context only: it is not authentication, login, ownership or possession proof, verified identity, membership, trust, or authorization. Selection never loads the participant view, grants authority, or retains the provider; the existing separate one-shot submission and manual public-key path remain unchanged.

The live product shell has no viewer switching, composer, reactions, messages, mutation, signing, publishing, persistence, retry, polling, refresh, source discovery, or production defaults. The selected public key is not authenticated, and the view does not prove ownership, legal identity, membership, friendship, sponsor trust, or covenant authority. Only a formatter-valid external HODLXXI Limited or Full assertion controls its badge; all other authority outcomes fail closed to Limited and public Nostr data cannot elevate status.

This visual projection reflects external read-only authority; Social does not grant Full and never projects Operator. The page does not authenticate the subject, prove possession of a private key, issue status, persist state, retry, poll, discover an origin, or enable production mode. The ordinary synthetic application and separate Nostr developer page remain unchanged.

The dev page labels `DEV / LIVE PUBLIC NOSTR DATA` separately from `DEMO VIEWER / AUTHORITY NOT LIVE`. Its local demo viewer is not authenticated, and Nostr data cannot provide HODLXXI membership, Full or Operator status, CRT validity, verified identity, sponsor trust, or covenant authority. Missing live authority remains fail-closed at Limited. The authenticated `web/index.html` entry does not import the live Nostr transport or select a relay on load; the prior synthetic application is retained only at `web/demo.html`.

Run the manual probe after merge with a caller-selected public relay (the relay below is deliberately a placeholder):

```text
node scripts/nostr-relay-probe.mjs --relay <explicit-wss-relay> --kind <0-or-1> --limit 3 --timeout-ms 5000
```

Optional `--author <64-hex-public-key>` narrows the request further; `--json` selects sanitized JSON output. The event limit is 1–10 (default 3), and the timeout is 250–30000 milliseconds (default 5000). Exit codes are 2 for arguments or relay configuration, 3 for transport failure, 4 for timeout, 5 for malformed relay results, and 6 for canonical validation failure. A successful read with no events exits successfully with `zero-events`.

Implemented now: the authenticated Social product entry, local-only authenticated rehearsal, opaque Social sessions, same-origin session/authority/logout endpoints, server-side read-only HODLXXI Limited/Full projection, fail-closed Limited fallback, isolated synthetic demo, explicit developer-only public-feed previews, bounded one-shot Nostr and HODLXXI probes, and the existing normalized composition/service boundaries. None of these code paths constitutes a production deployment.

Not implemented: production deployment, production OAuth client registration and secret provisioning, automatic relay or source selection, relay discovery or pools, reconnect, persistent subscriptions, polling, personalized live feeds, signing, publishing, DMs, encryption, NIP-07 signing or account management, durable shared session persistence, or horizontal-scale session coordination. V1.14 authentication and session-bound authority are implemented in code, but they are not deployed as a live production authentication service.

Successful probe output means “a public Nostr relay read succeeded and accepted events passed current validation.” It does not mean HODLXXI membership, Full or Operator status, CRT, identity ownership, relay trust, or content trust was verified.

Not implemented: default live social-data mode, relay discovery, relay pools, reconnect, persistent subscriptions, publishing, signing, DMs, encryption, NIP-07 signing or account management, NIP-44, NIP-59, NIP-65, production relay selection, private-key access, CRT issuance, covenant or chain validation, sponsor/status mutation, writes to HODLXXI, durable shared session storage, or production deployment. OAuth login and session-bound authority are implemented in code in V1.14, but production OAuth registration, credential provisioning, and deployed live login remain separate work. The ordinary authenticated viewer now comes only from the opaque Social session subject.

The authenticated `web/index.html` is designed to run behind the same-origin Social BFF and its `/auth/*` routes; opening it as a standalone static file does not create an authenticated session. For deterministic local product exploration, serve `web/demo.html`: its viewer selector is explicitly synthetic, in-memory, and not a login. Run `node --test` for deterministic Node built-in tests.

For an explicit manual development check of the Nostr-only developer surface, open `web/dev-live.html`, enter a developer-selected public `wss://` relay, choose **Read once**, and confirm bounded accepted public notes or an explicit empty/failure state. The deterministic synthetic shell is now `web/demo.html`. Automated tests inject fake transports and never access a live relay or production HODLXXI origin.

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
