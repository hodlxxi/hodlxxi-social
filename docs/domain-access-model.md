# Domain and access model

A participant is identified by a normalized 32-byte Nostr public key rendered as 64 lowercase hexadecimal characters. Display names are presentation metadata and carry no authority.

The three presentation/access states are:

- **Limited**: safe fallback without current objective CRT proof; direct-friend content only.
- **Full**: derived only from a current supported CRT assertion; includes friend-of-friend discovery.
- **Operator**: covenant/operator-level assertion supplied by CRT; Social cannot grant it.

Assertions are consumed, never authored by Social. A displayed role is not legal identity. Status changes do not arise from social activity, sponsorship, friendship, or manual application controls.

V1.21 adds a separate protected-content decision boundary. `FULL_NETWORK` reads and writes require an authenticated subject plus a current exact-subject external Full assertion; Operator is not a protected-content grant. All other authority inputs deny, and denied reads disclose only one generic empty result. See [Protected Content Boundary V1](PROTECTED_CONTENT_BOUNDARY_V1.md).

V1.2 consumes assertions through a separately injected read-only HODLXXI/CRT adapter. A valid Limited assertion remains valid evidence with preserved provenance while its presentation stays Limited. Full and Operator presentation can arise only from current canonical `hodlxxi-crt` assertions. Missing transport, transport failure, malformed or unknown fields, unsupported versions or sources, mismatched subjects, invalid evidence, and expiry are invalid authority evidence and fail closed to Limited. This boundary does not authenticate viewers, issue CRT, validate covenants or chain state, mutate sponsors/status, or write to HODLXXI.
