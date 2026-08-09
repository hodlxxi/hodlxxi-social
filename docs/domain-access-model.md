# Domain and access model

A participant is identified by a normalized 32-byte Nostr public key rendered as 64 lowercase hexadecimal characters. Display names are presentation metadata and carry no authority.

The three presentation/access states are:

- **Limited**: safe fallback without current objective CRT proof; direct-friend content only.
- **Full**: derived only from a current supported CRT assertion; includes friend-of-friend discovery.
- **Operator**: covenant/operator-level assertion supplied by CRT; Social cannot grant it.

Assertions are consumed, never authored by Social. A displayed role is not legal identity. Status changes do not arise from social activity, sponsorship, friendship, or manual application controls.
