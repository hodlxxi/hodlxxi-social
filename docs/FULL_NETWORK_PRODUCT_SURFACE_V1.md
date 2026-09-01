# Full Network Product Surface V1.23

V1.23 adds the first browser-visible Full Network area to the ordinary authenticated HODLXXI Social product. It is a product shell only and consumes the existing session-bound, read-only HODLXXI authority projection without creating or upgrading membership.

## Implemented now

- Authenticated browser-visible Full Network navigation and surface.
- Access gated by the existing accepted Full authority projection: `status == "full"` and `valid == true` for the exact authenticated session subject.
- Generic unavailable routing for Limited or fail-closed authority, without revealing participant existence or counts.
- An honest disconnected-directory state that renders no participant records, aliases, or other participants' identity keys.

## Not implemented

- Live participant directory.
- Aliases.
- Presence.
- Protected transport.
- X25519.
- Payments.
- Nostr membership publication.

V1.24 adds the disabled-by-default, source-only [Full Directory BFF](FULL_DIRECTORY_BFF_V1.md). When separately configured and activated, the existing surface can render only accepted viewer-private opaque aliases. No production activation, synthetic participant fallback, names, presence, messaging, protected Full posts, encryption/decryption, or participant-key disclosure is included.
