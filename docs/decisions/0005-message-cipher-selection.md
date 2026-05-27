# Message Cipher Selection

**Date:** 2026-04-21
**Status:** Accepted

## Decision

XChaCha20-Poly1305 (via the `chacha20poly1305` crate's `XChaCha20Poly1305` type, 24-byte nonce) is the AEAD cipher for every ratcheted message in Aether.

## Why

- Chosen over AES-256-GCM — budget Android SoCs lack guaranteed ARMv8 AES instructions, and software AES is cache-timing-sensitive on cores without hardware support. ChaCha-family ciphers run at constant speed in software regardless of hardware
- Chosen over ChaCha20-Poly1305 — the 24-byte extended nonce tolerates HKDF-derived or random nonces without collision concern. The 12-byte variant's 2³² birthday bound is incompatible with derived-nonce schemes
- Shares audit surface with [DR 0002](0002-cryptographic-primitive-selection.md) Curve25519 primitives, one family of constructions to review
- Implementation is a RustCrypto audited crate used in production protocols
