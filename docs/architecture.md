# Architecture

## Implemented through V1.3

The dependency direction is `explicitly selected sources → source validation and normalization → composition root → Social data service → visibility/access projection → web UI`. Canonical identity, access, visibility, and Nostr validation remain in `src/domain.mjs`, `src/visibility.mjs`, and `src/nostr.mjs`; adapters do not import rendering code.

`createComposedSocialDataService({ socialAdapter, authorityAdapter, now })` is the single V1.3 construction seam. The caller must inject the social source and may separately inject an authority source. The composition root only forwards those owned inputs to the existing service. It has no registry, generic merge, capability union, transport, source discovery, environment/hostname/URL inspection, or fallback selection. The deterministic browser application explicitly selects `SyntheticSocialAdapter` and the local fixture-backed `HodlxxiAuthorityReadAdapter`.

Domain ownership is fixed rather than inferred from argument or adapter ordering. Participants, profiles, feed, follows, friendship, sponsor-trust edges, groups, messages, and notifications belong to the social adapter. External Limited/Full/Operator assertions belong only to the HODLXXI authority adapter. Synthetic status-like state, Nostr metadata or follows, friendship, and sponsor trust cannot overwrite or elevate authority. Raw Nostr and runtime payloads remain inside their source-specific boundaries; only normalized Social records reach the service snapshot and UI.

The adapter declares a closed capability list. The service checks that declaration before each small read operation, rejects malformed adapter results, and normalizes accepted values into immutable participants, typed relationship edges, posts, groups, conversations, notifications, and external-access records. An implemented method does not imply a capability. Missing capabilities fail explicitly.

SyntheticSocialAdapter remains the active application adapter. It reads deterministic fixtures and has no generic query or connector. Groups, conversations, and notifications are fixture data below the adapter rather than rendering-module defaults. The product receives one normalized snapshot, so profile, feed, Circle, search/discovery, messaging/groups, and notifications/activity share the same viewer-scoped source.

`NostrPublicReadAdapter` is the first protocol-specific alternative at the same injected adapter boundary. Its caller supplies a narrow transport with `read(filter)` and the local current viewer. Initialization requests only public kinds `0` and `1`, delegates event validation and mapping to `src/nostr.mjs`, minimizes accepted profiles and notes into immutable Social records, and retains no raw relay payload. It supplies empty local/demo relationship, group, conversation, and notification collections and cannot supply external access assertions. It has no live source selection, generic connector, signing, or publication operation.

CRT is a separately injected external read-only authority boundary. `HodlxxiAuthorityReadAdapter` declares only `READ_EXTERNAL_AUTHORITY` and accepts only a narrow injected `readAssertion(subject)` transport. The Social service reads social collections from its social adapter and assertions from its authority adapter, then canonical normalization records subject, asserted status, source, validity/fallback, and optional evidence reference. Missing transports and transport failures produce unavailable assertions; expired, mismatched, malformed, arbitrary-source, or unsupported assertions resolve to Limited. Valid Limited evidence remains valid and retains provenance. Social cannot author, grant, upgrade, or mutate Full or Operator status. Friend edges and sponsor-trust edges remain separate; neither is traversed as authority.

Demo posts, reactions, messages, and notification read choices remain local ephemeral browser state. `LOCAL_EPHEMERAL_WRITES` describes that product behavior only; it is not external publication.

## Not implemented

A future deployment may inject production relay or runtime reads, but live relay selection, live HODLXXI runtime selection, environment-based configuration, and automatic production detection or network connection are not implemented. Authentication, signing, publishing, DMs, encryption, NIP-07, NIP-44, NIP-59, private keys, CRT issuance, covenant/Bitcoin-chain validation, sponsor or status mutation, HODLXXI writes, and production deployment are also not implemented.

There is no active relay, built-in WebSocket or HTTP/RPC connector, production URL, database, persistence, environment-secret access, signing, publication, private-key handling, custody, Bitcoin spending, Lightning payment, status issuance, deployment authority, or dependency on Universal-Bitcoin-Identity-Layer.
