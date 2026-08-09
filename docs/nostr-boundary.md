# Nostr boundary

Nostr public keys map one-to-one to participant IDs. V0 maps kind `0` profile events and kind `1` text notes into small immutable domain records. Validation occurs before mapping.

`createNostrBoundary` remains the canonical injectable validation seam for future relay transport. It validates public relay filters and events before delegating; event mapping also validates before producing domain records. The Social data service never passes raw relay JSON to rendering code.

No Nostr adapter is active in V1. SyntheticSocialAdapter supplies local fixtures and does not call this boundary. Relay reads, public-event ingestion, and publication are future integration work; external publication is unsupported by the active V1 capability model. The repository has no built-in relay URL, WebSocket, live relay requirement, signer, or secret loader. It does not request, generate, accept, persist, or control private keys.
