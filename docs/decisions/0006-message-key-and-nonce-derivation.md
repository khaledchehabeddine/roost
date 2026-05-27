# Message Key and Nonce Derivation

**Date:** 2026-04-21
**Status:** Accepted

## Decision

Each ratchet message key is expanded via HKDF-SHA256 with a protocol-specific info string and no salt into a 32-byte XChaCha20-Poly1305 encryption key and 24-byte nonce. The nonce is not transmitted, the receiver re-derives it from its own symmetrically derived message key.

## Why

- Avoids transmitting the 24-byte nonce with each message
- Each message key is used exactly once, so random nonce adds no security over a deterministic one
- A distinct HKDF info string domain-separates this derivation from other HKDF outputs in the crate, preventing cross-protocol key reuse
- Salt is omitted per RFC 5869 §3.1 — the chain-derived message key is already pseudo-random
