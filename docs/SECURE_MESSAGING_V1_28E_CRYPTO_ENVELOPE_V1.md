# Social V1.28E Crypto Envelope V1

## Status and boundary

V1.28E freezes the browser-side content-encryption construction and the
`hodlxxi.social_message_envelope.v1` contract. It returns one encrypted
envelope in memory. It does not enable the composer, submit ciphertext, add a
server message route, store an envelope, deliver a message, or decrypt a
message. Those operations remain V1.28F/V1.28G work.

The content path remains:

```text
sender browser -> local plaintext encryption -> ciphertext-only server -> recipient browser -> local decryption
```

The encryption module accepts exactly `recipientPackage` and `plaintext`.
Production callers cannot select a message identifier, nonce, content key,
clock, private key, canonical subject, or recipient capability. Failures
collapse to the non-sensitive error `message encryption unavailable`.

## VERIFIED FACTS: cryptographic selection and provenance

The reviewed dependency is [`@hpke/core` 1.9.0](https://www.npmjs.com/package/@hpke/core),
exact-pinned in `package.json` and `package-lock.json`. The npm package is MIT
licensed, comes from
[`dajiaji/hpke-js`](https://github.com/dajiaji/hpke-js), requires Node 16 or
later, and has registry integrity:

```text
sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==
```

Its one installed runtime dependency is the same-upstream MIT package
`@hpke/common` 1.10.1, resolved exactly by the lock with integrity:

```text
sha512-moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==
```

Upstream documents an RFC 9180 implementation built on WebCrypto, the required
X25519, HKDF-SHA256, and AES-GCM support, browser support including Chrome, and
Node 18 support. Upstream also documents passing the official RFC 9180 vectors
and Project Wycheproof ECDH/X25519 vectors. The repository test runs the
official CFRG Base-mode vector for KEM `0x0020`, KDF `0x0001`, and AEAD
`0x0001`; the complete downloaded vector source had SHA-256
`61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`.

Upstream explicitly states that the library has not been formally audited.
That is a residual risk, not an audit claim. The historical critical
[CVE-2025-64767 / GHSA-73g8-5h73-26h4](https://github.com/dajiaji/hpke-js/security/advisories/GHSA-73g8-5h73-26h4)
affected `@hpke/core <=1.7.4` through concurrent sender-context nonce reuse and
was patched starting at 1.7.5. Version 1.9.0 is outside that affected range.
V1.28E additionally creates a fresh suite and invokes its single-shot `seal`
operation once per target device. No mutable sender context is shared across
devices or messages.

The npm audit executed on 2026-09-08 reported zero vulnerabilities for the
locked production and development dependency tree.

The selected construction is RFC 9180 Base mode:

- DHKEM(X25519, HKDF-SHA256), KEM ID `0x0020`;
- HKDF-SHA256, KDF ID `0x0001`;
- AES-128-GCM, AEAD ID `0x0001`;
- native WebCrypto AES-256-GCM for the message body.

No Auth-mode sender key, Ed25519 key, NIP-07 signature, UBID signature,
Bitcoin signature, participant private key, or persisted Social device private
key participates in outbound encryption.

## Local browser delivery

The browser has no runtime CDN or package-registry dependency.
`scripts/build-v128e-hpke-browser.mjs` uses exact-pinned, dev-only `esbuild`
0.28.2 (MIT, registry integrity
`sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==`)
to tree-shake the four required exports into
`web/vendor/hpke-core-v1.9.0.mjs`. The build targets Chrome 111 syntax and
replaces the upstream Node `crypto` fallback with an in-bundle fail-closed
stub. A supported browser therefore uses `globalThis.crypto.subtle`; an
unsupported browser cannot try a Node module or remote fallback. The artifact
contains no runtime imports or URLs. The adjacent
`web/vendor/hpke-js-MIT-LICENSE.txt` preserves the upstream redistribution
notice. The server need expose only the existing reviewed `web/` assets, never
`node_modules`.

The build command is:

```text
node scripts/build-v128e-hpke-browser.mjs
```

Build determinism is checked by building twice from the same lock-installed
inputs and comparing SHA-256 outputs. Both builds produced
`9f5eb8be623357983b9862b7e2513fad98d4afdc3ccac869bec315eaf40f43dc`.
The committed generated artifact is not
imported by the authenticated entry graph in V1.28E, so this phase does not
activate live UI encryption.

Local compatibility validation ran on Node 18.19.1 with its native WebCrypto
X25519 implementation and a browser-shaped `globalThis.crypto`, including the
official RFC 9180 suite vector. The generated module is syntax-targeted to
Chrome 111 and contains no Node or remote-module import. Upstream confirms
Chrome support. No Chrome executable was installed in this validation
environment, so this is not represented as a live Chrome browser run.

## Recipient package gate

The browser independently accepts only the V1.28D closed package with exact
top-level and device fields. It verifies schema/version/source/completeness,
the `p_` alias syntax, integer Unix-millisecond validity, current package and
device validity, 1..16 devices, strictly increasing unique `d_` handles,
unique X25519 public keys, binding version 1..1024, canonical lowercase
32-byte X25519 encodings, prohibited low-order encodings, and consistency
between device and package validity windows. It recomputes the V1.28D
canonical SHA-256 snapshot evidence and requires the exact supplied
`snapshotId`. Unknown fields, accessors, symbols, sparse/extended arrays,
duplicates, malformed values, future packages, and expired evidence fail
closed. Timestamp units are never inferred by magnitude.

## Per-message construction

For each call the browser obtains all production randomness from
`globalThis.crypto.getRandomValues` or the HPKE library's WebCrypto path:

1. Generate 32 random bytes and encode them as an unpadded 43-character
   base64url value prefixed by `m_`.
2. Generate one fresh 32-byte `K_message`.
3. UTF-8 encode the non-empty text. Reject more than 16,384 bytes without
   truncation.
4. Generate a fresh random 12-byte AES-GCM nonce and encrypt the body once with
   non-extractable WebCrypto AES-256-GCM and the authenticated header below.
5. For each recipient device, create an independent HPKE suite and one-shot
   Base-mode seal. Wrap the same 32-byte `K_message` with that device's public
   X25519 key.
6. Return the frozen ciphertext envelope. Do not return or persist
   `K_message`. The implementation makes a best-effort overwrite of its byte
   arrays after use; JavaScript does not guarantee secure erase.

V1.28E does not wrap `K_message` for sender history devices. Sender
cross-device Sent history and historical multi-device rewrap remain deferred
to V1.28G.

## Frozen envelope V1

The exact serialized field sets are:

```json
{
  "schema": "hodlxxi.social_message_envelope.v1",
  "version": 1,
  "suite": "hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1",
  "messageId": "m_<43 unpadded base64url characters>",
  "recipientPackageSnapshotId": "sha256:<64 lowercase hex characters>",
  "recipientDeviceHandles": ["d_<22 base64url characters>"],
  "body": {
    "algorithm": "aes-256-gcm",
    "nonce": "<unpadded base64url of 12 bytes>",
    "ciphertext": "<unpadded base64url of UTF-8 length + 16 bytes>"
  },
  "keyWraps": [
    {
      "deviceHandle": "d_<22 base64url characters>",
      "algorithm": "hpke-base-x25519-hkdfsha256-aes128gcm-v1",
      "enc": "<unpadded base64url of 32 bytes>",
      "ciphertext": "<unpadded base64url of 48 bytes>"
    }
  ]
}
```

`recipientDeviceHandles` is strictly lexicographically sorted and unique.
`keyWraps` has the same order and exactly one entry per handle. The envelope
has no timestamp. It contains no recipient alias/capability, raw recipient
public key, canonical subject, device ID, binding ID, Bitcoin/Nostr/XPUB data,
private label, plaintext, plaintext content key, or private CryptoKey.

## Authenticated header, HPKE info, and AAD

The authenticated header is UTF-8 of this no-whitespace JSON representation,
with properties always emitted in the shown order:

```text
{"schema":"hodlxxi.social_message_envelope.v1","version":1,"suite":"hodlxxi-hpke-x25519-hkdfsha256-aes128gcm-aes256gcm-v1","messageId":"<messageId>","recipientPackageSnapshotId":"<snapshotId>","recipientDeviceHandles":["<sorted handles>"],"bodyAlgorithm":"aes-256-gcm"}
```

The implementation constructs this representation from validated values; it
does not serialize caller property insertion order. These exact bytes are the
AES-256-GCM body AAD.

For each HPKE wrap:

```text
info = ASCII("HODLXXI_SOCIAL_MESSAGE_KEY_WRAP_V1") || 0x00 || ASCII(messageId)
aad  = authenticated_header_bytes || 0x00 || ASCII(target_deviceHandle)
```

This binds schema, version, suite, message ID, recipient package snapshot,
complete sorted recipient device list, body algorithm, and exact target device
handle. Recipient aliases and raw public keys are deliberately absent.

## SECURITY NON-CLAIMS

- V1.28E V1 gives end-to-end content confidentiality and cryptographic
  ciphertext integrity, but does not claim cryptographic sender-identity
  authentication against a malicious HODLXXI server. Sender attribution
  remains authenticated by the existing server/session authority.
- Crypto alone cannot detect replay of an unchanged valid envelope. Duplicate
  `messageId` rejection belongs to V1.28F/V1.28G storage and delivery.
- There is no sender cross-device Sent history in V1.28E.
- RFC 9180 Base mode does not give forward secrecy for retained historical
  wraps after compromise of the recipient's static private device key beyond
  the properties RFC 9180 itself provides.
- Content is encrypted; routing metadata such as opaque device handles and a
  package snapshot identifier is not hidden from the later server path.
- JavaScript best-effort byte overwrites are not guaranteed secure erase.
