# Protected Content Boundary V1

V1.21 adds a deterministic, offline, fail-closed foundation for later protected content. It defines only `PUBLIC` and `FULL_NETWORK`, separate read and write authorization decisions, a generic non-disclosing denied-read result, bounded current-Full recipient validation, an opaque protected-envelope shape, and narrow injected contracts for recipient resolution, transport, envelope production and envelope opening.

`PUBLIC` preserves the V1.20 public model. `FULL_NETWORK` requires an authenticated canonical public-key subject and a current, supported, exact-subject external `Full` assertion for both writing and reading. Limited, Operator, expired, unavailable, malformed, mismatched, unsupported and unknown authority deny. Friendship, sponsor trust, Nostr metadata, synthetic data and caller-supplied status are never authority. Social consumes authority and never grants Full or Operator.

Every denied protected read returns the same empty result. It does not reveal author identity, post existence, identifiers, counts, recipients, timestamps, search information or notification information.

The envelope is explicitly opaque, rejects plaintext-bearing fields and is separate from public Nostr kinds 0 and 1. The contract name does not claim that encryption exists or is correct. No existing public Nostr adapter accepts protected plaintext, and V1.21 is not imported into the authenticated public read/write or production composition paths.

Before Full Network can be enabled, a future implementation must supply and verify an authoritative member directory, key distribution, rotation and revocation, durable protected transport, actual encryption and envelope cryptography, and production UI. Recipient resolution, durable storage, live transport, relays, databases, filesystem persistence, production routes, server signing, private-key access and key custody are not implemented here.
