# Nostr boundary

Nostr public keys map one-to-one to participant IDs. The canonical boundary maps signed kind `0` profile events and kind `1` text notes into small immutable domain records. Validation occurs before mapping.

`src/nostr.mjs` remains authoritative for public filter and event validation. `NostrPublicReadAdapter` accepts an explicitly injected transport with `read(filter)`, requests only kinds `0` and `1`, and calls the canonical event mappers before producing minimized participant and feed records. Raw events, metadata fields, tags, and signatures are not retained in Social records or passed to rendering code.

`READ_PUBLIC_NOSTR` explicitly identifies this read-only capability. The adapter has no `READ_EXTERNAL_AUTHORITY` capability or assertion operation. It is initialized into an immutable snapshot and then satisfies the social side of the service contract; application rendering does not know transport details. The current viewer is separately injected local state and is not proof of authentication or key ownership. Nostr metadata cannot supply CRT assertions, elevate Limited to Full or Operator, or create sponsor/covenant trust. Contact/follow events and all other kinds are rejected rather than interpreted as trust.

SyntheticSocialAdapter remains fully supported and is still used by the application shell. V1.2 composes it with a separate deterministic HODLXXI authority-read seam. Live production relay/runtime selection, signing, publishing, DMs, encryption, NIP-07, NIP-44, NIP-59, private keys, production authentication, authority mutation, and HODLXXI writes remain unimplemented. The repository has no built-in relay or runtime URL, generic HTTP/RPC connector, signer, or secret loader.

## V1.4 controlled public read transport

`WebSocketNostrReadTransport` is the first concrete relay transport. It is constructed only with an explicit validated `wss://` relay URL and exposes only `read(filter)`. It has no built-in relay hostname and does not inspect environment variables, browser location, storage, or cookies. The normal application does not import or construct it and remains on `SyntheticSocialAdapter`.

One read owns one WebSocket. It validates the public filter through the canonical filter boundary, sends one `REQ` with a local opaque subscription ID, accepts matching `EVENT` frames, and completes on `EOSE` or the configured event count. It then sends `CLOSE` where the request was established and closes the socket. Open and overall timers, maximum event count, maximum message size, and maximum accumulated data bound the lifecycle. Connection failures, premature closure, timeouts, malformed or unknown frames, relay notices, and wrong subscription IDs fail explicitly and trigger cleanup. There is no reconnect, persistent listener, daemon, or relay pool.

The transport parses only the relay envelope. Returned event objects are still untrusted and must pass `NostrPublicReadAdapter` and `src/nostr.mjs` validation before minimized Social records exist. Relay data cannot provide `READ_EXTERNAL_AUTHORITY`, grant Full or Operator, replace HODLXXI/CRT assertions, or reach rendering as raw relay objects. Tests inject a deterministic fake WebSocket and make no live connection.

Default live mode, relay discovery, relay pools, reconnect, persistent subscriptions, production relay selection, publishing, signing, DMs, encryption, authentication, NIP-07, NIP-44, NIP-59, NIP-65, and a live HODLXXI runtime transport are not implemented.

## V1.5 developer-only manual probe

`scripts/nostr-relay-probe.mjs` is a manual, one-shot developer harness. Every invocation requires a caller-supplied `wss://` relay and kind `0` or `1`; an optional canonical author key narrows the filter. The event limit is bounded from 1 through 10 and the timeout from 250 through 30000 milliseconds. No relay is built in, inferred from an environment or hostname, discovered, selected by the product, or persisted.

The probe-local transport facade preserves the existing adapter contract while narrowing its actual request to the explicit single kind, optional author, and limit. The path is the existing `WebSocketNostrReadTransport`, then `NostrPublicReadAdapter`, then canonical `src/nostr.mjs` mapping. One invocation performs one read and exits. There is no reconnect, pool, daemon, background subscription, publishing, signing, private-key input, AUTH handling, encryption, DM support, or authority lookup.

Human and explicit `--json` output contain only the relay, requested filter, bounded counts, completion reason, bounded elapsed time, and minimized normalized profile or note diagnostics. Raw frames, arbitrary relay fields, tags, signatures, and unknown metadata are not printed. Empty reads complete successfully as `zero-events`; argument, transport, timeout, malformed-result, and canonical-validation failures have deterministic nonzero categories. Automated tests inject the transport and adapter seams and do not connect to the internet.

Successful probe output means “a public Nostr relay read succeeded and accepted events passed current validation.” It does not verify HODLXXI membership, Full or Operator status, CRT, identity ownership, relay trust, or content trust. It does not establish legal identity, covenant trust, or any HODLXXI authority.

## V1.6 explicit development live preview

`web/dev-live.html` is a separate opt-in development page; the normal `web/index.html` application remains synthetic/offline and imports no live transport. The page starts idle with no relay value and requires a developer-entered `wss://` URL. It does not inspect environment variables, browser hostname, URL parameters, local storage, session storage, IndexedDB, or cookies, and it does not persist the relay or results.

Each **Read once** action constructs one `WebSocketNostrReadTransport` with a default event bound of 3, a maximum of 10, and 5-second open/read timeouts. That transport is injected into `NostrPublicReadAdapter`, whose normalized snapshot passes through `createComposedSocialDataService` and `SocialDataService`. `src/nostr.mjs` remains authoritative; the page does not parse events in parallel. Completion, zero events, invalid relay input, connection failure, timeout, malformed frames, and canonical validation rejection are explicit states. A failed read clears prior results and never substitutes synthetic posts.

Only normalized author key, timestamp, and bounded note body fields reach the preview, and relay-controlled values are assigned as DOM text. Raw frames, tags, signatures, unknown metadata, and executable HTML are not rendered. The labels `DEV / LIVE PUBLIC NOSTR DATA` and `DEMO VIEWER / AUTHORITY NOT LIVE` keep source truth separate. The viewer is local demo state, not authentication or proof of key ownership; no authority adapter is injected, so every live participant remains Limited/fail-closed and Nostr cannot create Full, Operator, CRT validity, sponsor trust, or covenant authority.

There is no initial read, auto-refresh, interval, polling, reconnect, relay pool, persistent socket, signing, publishing, AUTH signing, private-key input, extension access, wallet access, DM/encryption support, or HODLXXI runtime call. Automated coverage injects fake WebSocket/transport behavior and performs no internet access. Production live mode, automatic source selection, relay discovery, personalized feeds, authentication, live HODLXXI authority, persistence, and deployment remain unimplemented.
