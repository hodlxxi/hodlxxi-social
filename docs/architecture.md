# Architecture

## Implemented in V1

The dependency direction is `web UI → Social data service → explicit adapter contract → SyntheticSocialAdapter`. Canonical identity, access, visibility, and Nostr validation remain in `src/domain.mjs`, `src/visibility.mjs`, and `src/nostr.mjs`; adapters do not import rendering code.

The adapter declares a closed capability list. The service checks that declaration before each small read operation, rejects malformed adapter results, and normalizes accepted values into immutable participants, typed relationship edges, posts, groups, conversations, notifications, and external-access records. An implemented method does not imply a capability. Missing capabilities fail explicitly.

SyntheticSocialAdapter is the only active adapter. It reads deterministic fixtures and has no generic query or connector. Groups, conversations, and notifications are fixture data below the adapter rather than rendering-module defaults. The product receives one normalized snapshot, so profile, feed, Circle, search/discovery, messaging/groups, and notifications/activity share the same viewer-scoped source.

CRT is an external read-only authority boundary. Assertion normalization records subject, asserted status, source, validity/fallback, and optional evidence reference. Existing canonical access derivation resolves missing, expired, mismatched, malformed, or unsupported assertions to Limited. Social cannot author, grant, upgrade, or mutate Full or Operator status. Friend edges and sponsor-trust edges remain separate; sponsor-trust is never traversed as social reachability.

Demo posts, reactions, messages, and notification read choices remain local ephemeral browser state. `LOCAL_EPHEMERAL_WRITES` describes that product behavior only; it is not external publication.

## Future integration seams

A future Nostr adapter may inject relay reads and validated public-event ingestion through `src/nostr.mjs`. External publication remains unsupported in V1. A future HODLXXI/CRT adapter may consume read-only runtime assertions; it must not reproduce covenant validation or expose authority mutation.

There is no active relay, WebSocket, HTTP/RPC connector, production URL, database, persistence, environment-secret access, signing, private-key handling, custody, Bitcoin spending, Lightning payment, status issuance, deployment authority, or dependency on Universal-Bitcoin-Identity-Layer.
