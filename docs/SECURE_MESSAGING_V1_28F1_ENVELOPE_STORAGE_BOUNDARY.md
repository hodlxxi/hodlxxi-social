# Social V1.28F.1 Exact Ciphertext Envelope Boundary

## Status

V1.28F.1 is a messaging-inert server envelope and future storage boundary. It
adds exact in-memory normalization, canonical wire serialization, canonical
wire parsing, and a domain-separated digest for the browser envelope frozen by
V1.28E. It does not submit, route, persist, retrieve, deliver, or decrypt a
message.

The implementation is
`src/server/message-envelope-v128f1.mjs`. Importing it performs no work beyond
module definition. It is not imported by the server composition root, BFF, or
authenticated browser graph.

## Accepted envelope

The only accepted schema is `hodlxxi.social_message_envelope.v1`, version `1`,
with suite
`hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1`. The exact top-level
field order used for normalized output and canonical wire is:

```text
schema, version, suite, messageId, recipientPackageSnapshotId,
recipientDeviceHandles, body, keyWraps
```

The exact body order is `algorithm, nonce, ciphertext`; the body algorithm is
`aes-256-gcm`. The exact wrap order is
`deviceHandle, algorithm, enc, ciphertext`; the wrap algorithm is
`hpke-base-x25519-hkdfsha256-aes128gcm-v1`.

The normalizer requires only own enumerable data properties. Missing, extra,
inherited, accessor, symbol, null-prototype, custom-prototype, proxy, sparse,
and extended shapes fail closed. All failures expose only the `TypeError`
message `message envelope unavailable`. Rejected values are not included in an
error or logged. The result is a fresh, deeply frozen object containing only
the frozen ciphertext-envelope fields.

The exact bounds are:

- `messageId`: `m_` plus 43 canonical unpadded base64url characters decoding
  to exactly 32 bytes;
- recipient package snapshot: `sha256:` plus 64 lowercase hexadecimal
  characters;
- recipient device handles: 1 through 16 `d_` plus 22 base64url-character
  handles, strictly lexicographically increasing and unique;
- body nonce: canonical unpadded base64url decoding to exactly 12 bytes;
- body ciphertext: canonical unpadded base64url decoding to 17 through 16,400
  bytes, inclusive;
- key wraps: exactly one per device handle and in exactly the same order;
- HPKE encapsulation: canonical unpadded base64url decoding to 32 bytes;
- wrapped-key ciphertext: canonical unpadded base64url decoding to 48 bytes.

These are the V1.28E envelope bounds. V1.28F.1 does not redesign the browser
envelope or its cryptography.

## Canonical wire

The canonical wire form is no-whitespace ASCII JSON constructed explicitly in
the field orders above. It never depends on caller property insertion order.
For an envelope returned by V1.28E, it is byte-identical to that module's
`JSON.stringify(envelope)` output.

The raw-wire entry accepts a string, `Buffer`, or exact `Uint8Array`. Input is
limited to 32,768 bytes and every byte/code unit must be ASCII. After
`JSON.parse`, the exact normalizer runs and the module reserializes the result.
The original input must equal that canonical serialization byte for byte.
Consequently whitespace, reordered fields, alternate JSON escapes, duplicate
JSON members, base64url padding, and other noncanonical representations cannot
be accepted through JSON normalization.

## Canonical digest

The envelope digest bytes are:

```text
SHA-256(
  ASCII("HODLXXI_SOCIAL_MESSAGE_ENVELOPE_DIGEST_V1") ||
  0x00 ||
  ASCII(canonical_wire)
)
```

The only returned representation is:

```text
hodlxxi-social-message-envelope-v1-sha256:<64 lowercase hex characters>
```

This versioned form is intentionally distinct from the
`sha256:<64 lowercase hex characters>` recipient-package snapshot identifier.
The digest adds no sender tag, routing token, database identifier, retention
value, timestamp, or delivery state.

## Data boundary

Accepted output data is limited to the schema/version/suite constants, opaque
message identifier, recipient-package snapshot identifier, opaque device
handles, body nonce and ciphertext, and HPKE encapsulation and wrapped-key
ciphertext.

Normalized output, wire output, digest output, fixtures, and ordinary
diagnostics must not contain protected plaintext, a plaintext-derived preview,
plaintext `K_message`, a private key, a raw sender or recipient canonical
subject, a raw encryption public key, recipient alias or capability, device ID,
binding ID, OAuth/session/service token, private label, or Bitcoin, XPUB,
Nostr, sponsor, covenant, or friendship data. Tests use deterministic synthetic
byte patterns only.

## Deferred composition and storage

There is no HTTP route, durable or process-local message store, filesystem use,
PostgreSQL dependency, runtime composition, environment setting, browser
activation, inbox, submission path, decryption path, background task, staging
activation, or production activation in V1.28F.1.

Authorization, recipient routing, ciphertext storage, and inbox-read
dependencies remain documentary future boundaries. No executable port is
defined because its arguments and return values would prematurely freeze the
unresolved recipient-self routing semantics. In particular, this phase does
not choose a routing-token format or accept/derive a routing identifier from a
raw subject, public key, alias, capability, device ID, or binding ID.

Recipient routing remains blocked. Device-handle equivalence and stability
across the future routing and storage boundaries remain unproven. Retention,
quotas, opaque sender attribution, revocation retrieval, PostgreSQL schema,
HTTP routes, pagination, cursors, retries, delivery state, and inbox semantics
are deferred.

The next prerequisite is a separate UBID recipient-self routing gate. That
gate must be reviewed before authorization, transport, durable storage, or
inbox composition is designed or activated.
