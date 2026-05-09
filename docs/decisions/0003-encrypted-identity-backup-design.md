# Encrypted Identity Backup Design

**Date:** 2026-03-29
**Status:** Accepted

## Decision

Identity backups are a fixed 120-byte blob: `[salt (16B)] + [nonce (24B)] + [ciphertext (80B)]`. The passphrase is stretched with Argon2id (m=65536 KiB, t=3, p=1) into a 32-byte key. The payload is encrypted with XChaCha20-Poly1305. Salt and nonce are re-randomized on every export.

## Why

- **Argon2id** — Password Hashing Competition winner. Memory-hard design defeats GPU/ASIC brute-force at OWASP-baseline cost
- **XChaCha20-Poly1305 over AES-GCM** — 192-bit nonce eliminates collision risk when generated randomly, no nonce management needed
- **Poly1305 authentication tag** — wrong passphrase or any corruption is detected deterministically, no silent key corruption
- **Fixed-length, self-contained blob** — import validates with a single length check, no external metadata required
