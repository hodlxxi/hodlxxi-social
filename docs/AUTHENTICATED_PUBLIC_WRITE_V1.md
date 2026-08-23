# Authenticated Public Write V1.20

V1.20 permits an authenticated browser to publish a minimized public Nostr profile or note through an external signer. Social does not sign, hold keys, proxy events, or write to HODLXXI.

## Configuration and activation

The server accepts a separate optional `SOCIAL_NOSTR_PUBLISH_RELAY_URL`. It must be a canonical credential-free `wss://` URL and is not inferred from the read relay. After opaque Social session validation, exact `GET /auth/social-publish-config` returns only `{ "enabled": false }` or `{ "enabled": true, "relayUrl": "wss://…/" }`. It returns no subject, authority, OAuth value, relay credential, signer state, or fallback relay.

Page load never resolves an extension and never opens a write socket. The user must deliberately select **Connect signer**. The browser resolves `window.nostr` for that action only and calls `getPublicKey()` once. The result must be the exact lowercase 64-hex subject already supplied by `/auth/session`; a missing, malformed or different key disables publication with a fixed diagnostic. Social retains only the connected/mismatch/unavailable UI state, not the provider.

## One publication

Every profile or note submission performs this bounded sequence:

1. Resolve the external provider again and recheck `getPublicKey()` against the exact session subject.
2. Build one unsigned event with the current integer timestamp, empty tags and kind `0` or `1`.
3. Ask `signEvent()` for explicit extension approval.
4. Recompute and verify the returned NIP-01 event id and BIP340 signature locally, then require every returned event field to equal the requested field.
5. Open one WebSocket to the configured publish relay, send one `["EVENT", event]`, and accept only one exact `["OK", event.id, true, message]` within fixed bounds.
6. Close the socket and perform one bounded public-read refresh when a configured read relay is available.

There is no retry, reconnect, relay fallback, queue, draft storage, optimistic event injection, background publication or acknowledgement text exposure. Rejection, malformed output, timeout or transport failure produces one fixed failure state and leaves prior verified read data in place.

## Allowlisted public data

Kind `0` content is canonical JSON containing only non-empty normalized `display_name` (up to 80 characters) and/or `about` (up to 280 characters). Pictures, URLs, NIP-05 claims, relay lists, Lightning fields and unknown metadata are not published by this form.

Kind `1` content is non-empty normalized text bounded to 5,000 Unicode characters and 20,000 UTF-8 bytes. Both event types use an empty tag array in V1.20.

## Security, privacy and authority boundary

The external extension can observe the Social origin, the requested unsigned event and the user's approval decision. The publish relay can observe the browser network address, public key, event timestamp, public content and signature, and may retain or redistribute the accepted public event according to its own policy. Social stores none of those events or signer objects in a database, browser storage, cookie or server session.

Signing proves only that the returned public event verifies under its Nostr key. Publication does not grant or alter HODLXXI Limited/Full status, cannot create Operator, and is not friendship, sponsorship, CRT or covenant evidence. OAuth/session authentication remains the sole source of the viewer subject; HODLXXI remains the separate external read-only membership authority.

## Not included

V1.20 includes no private-key import/export, application or server signing, extension account switching, signer persistence, NIP-46, NIP-44, NIP-59, direct messages, encryption, follows, relay discovery, NIP-65 relay selection, media upload, deletion, reactions, reposts or HODLXXI writes.

NIP-07 is an optional browser-extension interface, so a compatible extension is an explicit runtime prerequisite rather than an application guarantee. Protocol references: [NIP-07 browser extension API](https://github.com/nostr-protocol/nips/blob/master/07.md) and [NIP-01 basic protocol flow](https://github.com/nostr-protocol/nips/blob/master/01.md).
