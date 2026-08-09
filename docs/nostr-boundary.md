# Nostr boundary

Nostr public keys map one-to-one to participant IDs. The canonical boundary maps signed kind `0` profile events and kind `1` text notes into small immutable domain records. Validation occurs before mapping.

`src/nostr.mjs` remains authoritative for public filter and event validation. `NostrPublicReadAdapter` accepts an explicitly injected transport with `read(filter)`, requests only kinds `0` and `1`, and calls the canonical event mappers before producing minimized participant and feed records. Raw events, metadata fields, tags, and signatures are not retained in Social records or passed to rendering code.

`READ_PUBLIC_NOSTR` explicitly identifies this read-only capability. The adapter has no `READ_EXTERNAL_AUTHORITY` capability or assertion operation. It is initialized into an immutable snapshot and then satisfies the social side of the service contract; application rendering does not know transport details. The current viewer is separately injected local state and is not proof of authentication or key ownership. Nostr metadata cannot supply CRT assertions, elevate Limited to Full or Operator, or create sponsor/covenant trust. Contact/follow events and all other kinds are rejected rather than interpreted as trust.

SyntheticSocialAdapter remains fully supported and is still used by the application shell. V1.2 composes it with a separate deterministic HODLXXI authority-read seam. Live production relay/runtime selection, signing, publishing, DMs, encryption, NIP-07, NIP-44, NIP-59, private keys, production authentication, authority mutation, and HODLXXI writes remain unimplemented. The repository has no built-in relay or runtime URL, WebSocket client, generic HTTP/RPC connector, signer, or secret loader.
