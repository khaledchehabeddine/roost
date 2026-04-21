# Message Key and Nonce Derivation

**Date:** 2026-04-21
**Status:** Accepted

## Decision

Each ratchet message key is expanded via HKDF-SHA256 (info: `HermesRatchet_MK`, salt: none) into a 32-byte XChaCha20-Poly1305 encryption key and a 24-byte nonce. The nonce is not transmitted — the receiver re-derives it from its own symmetrically-derived message key.

## Why

- Saves 24 bytes per message on the wire — meaningful under BLE MTU pressure (20-byte default, 247-byte negotiated)
- Each message key is used exactly once, so a random nonce adds no security over a deterministic one
- `HermesRatchet_MK` info string domain-separates this derivation from the handshake's `HermesX3DHLite` output, preventing cross-protocol key reuse
- Salt is omitted per RFC 5869 §3.1 — the chain-derived message key is already pseudo-random
