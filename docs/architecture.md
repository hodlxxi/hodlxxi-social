# Architecture

The browser UI depends on pure domain and visibility modules. Deterministic fixtures stand in for two replaceable ports: a Nostr relay adapter for public social events and a HODLXXI runtime/CRT assertion provider for covenant-derived status.

CRT is an external, read-only authority boundary. Social neither reproduces covenant rules nor issues, upgrades, or mutates Full/operator assertions. Missing, expired, malformed, or unsupported assertions resolve to Limited. Relay adapters transport public events only; key management and signing remain outside Social.

V0 has no server, persistence, network requirement, custody, or dependency on Universal-Bitcoin-Identity-Layer.
