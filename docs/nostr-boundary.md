# Nostr boundary

Nostr public keys map one-to-one to participant IDs. The canonical boundary maps signed kind `0` profile events and kind `1` text notes into small immutable domain records. Validation occurs before mapping.

`src/nostr.mjs` remains authoritative for public filter and event validation. `NostrPublicReadAdapter` accepts an explicitly injected transport with `read(filter)`, requests only kinds `0` and `1`, and calls the canonical event mappers before producing minimized participant and feed records. Raw events, metadata fields, tags, and signatures are not retained in Social records or passed to rendering code.

`READ_PUBLIC_NOSTR` explicitly identifies this read-only capability. The adapter is initialized into an immutable snapshot and then satisfies the same Social service contract as SyntheticSocialAdapter; application rendering does not know transport details. The current viewer is separately injected local state and is not proof of authentication or key ownership. Nostr metadata cannot supply CRT assertions, elevate Limited to Full or Operator, or create sponsor/covenant trust. Contact/follow events and all other kinds are rejected rather than interpreted as trust.

SyntheticSocialAdapter remains fully supported and is still used by the application shell. V1.1 does not implement live production relay selection, signing, publishing, DMs, encryption, NIP-07, NIP-44, NIP-59, private keys, a live HODLXXI/CRT adapter, or production authentication. The repository has no built-in relay URL, WebSocket client, generic HTTP/RPC connector, signer, or secret loader.
