# Authenticated Public Read V1.19

The ordinary authenticated product may read one operator-configured public Nostr relay. The server environment key is `SOCIAL_NOSTR_RELAY_URL`; it must parse to a canonical credential-free `wss://` URL. Production readiness fails when this value or any browser module in the revisioned graph is missing. V1.20 publication uses a separately configured relay and the independent boundary documented in `AUTHENTICATED_PUBLIC_WRITE_V1.md`.

After `GET /auth/session` accepts one lowercase x-only subject, `GET /auth/social-read-config` releases only the public relay URL. The browser never accepts a subject from the URL, form, extension, relay configuration, profile metadata, or relay event. It independently issues:

- one kind `0` request for at most four candidate metadata events;
- one kind `1` request for at most ten own public notes.

Each request uses the exact filter `authors: [session.subject]`, one allowed kind, and a fixed limit. Connections have fixed open/read, event-count, message-size, and accumulated-byte limits. They close after `EOSE` or the limit. There is no retry, reconnect, polling, persistent subscription, relay discovery, fallback, or background refresh.

The relay is untrusted. Before rendering, every event must have the exact NIP-01 wire fields, lowercase encodings, canonical SHA-256 event id, and a valid BIP340 secp256k1 signature. Events with an unexpected author or kind are rejected. Kind `0` selection uses the newest timestamp with the lowest id as the tie-breaker. Kind `1` results are deduplicated, newest-first, and capped at ten.

Only bounded plain text crosses into UI state: display name, bio, note text, timestamps, and shortened event ids. Pictures, external links, HTML, Markdown, NIP-05 claims, tags, raw relay frames, relay diagnostics, signatures, and unknown metadata do not render. Profile and post failures settle independently. The UI never replaces an empty or failed live result with a synthetic participant or post.

HODLXXI authority remains independent. A valid Nostr signature proves that the event was signed by its event key; it does not grant HODLXXI Full or Operator status, legal identity, covenant trust, sponsorship, friendship, content truth, or relay trust. Social has no signer or private key and performs no Nostr write.

Privacy boundary: the browser connects directly to the configured relay. That relay can observe the browser network address, timing, and queried public key. No OAuth credential, session cookie, HODLXXI authority response, or private key is sent to the relay.
