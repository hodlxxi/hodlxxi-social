# Nostr boundary

Nostr public keys map one-to-one to participant IDs. V0 maps kind `0` profile events and kind `1` text notes into small immutable domain records. Validation occurs before mapping.

`createNostrBoundary` accepts an adapter with `read` and `publish` functions, keeping relay selection replaceable. The foundation has no built-in relay URL and requires no live relay. It does not generate, accept, persist, or control private keys and does not sign events. Tests and UI use conspicuously synthetic public values and events.
