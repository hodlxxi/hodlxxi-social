# HODLXXI Social contributor rules

- Work only in this repository and keep it independent from Universal-Bitcoin-Identity-Layer.
- Treat participant public keys as identity; never add passwords, KYC authority, key custody, signing, or private-key persistence.
- Treat HODLXXI runtime/CRT as an external read-only authority. Social may consume assertions but must never grant Full or operator status.
- Keep social friendship separate from sponsor/covenant trust. Friendship is never proof of covenant trust.
- Keep V0 deterministic and offline: no databases, Redis, Bitcoin RPC, LND, relay requirement, deployment, or network-dependent tests.
- Preserve the non-claims in README.md and run the repository-local checks before handoff.
