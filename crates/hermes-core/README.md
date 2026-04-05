# hermes-core

Core domain logic. Manages the local device identity.

## Overview

`IdentityManager` is the central type — it generates, persists, and loads a device identity (an X25519 + Ed25519 key pair). It also supports encrypted backup via Argon2id key derivation and XChaCha20-Poly1305 encryption.

Storage is abstracted behind the `SecureStorage` trait so each platform can inject its own implementation. `InMemorySecureStorage` is provided for testing. `SecureStorage` requires `Send` because `IdentityManager` is shared across threads behind a `Mutex`.

## Dependencies

- `hermes-crypto` — key generation, signing, and Diffie-Hellman
- [`argon2`](https://github.com/RustCrypto/password-hashes) — Argon2id key derivation for encrypted backups
- [`chacha20poly1305`](https://github.com/RustCrypto/AEADs) — XChaCha20-Poly1305 authenticated encryption
- `zeroize` — scrubs derived keys and plaintext from memory-on-drop

## Constraints

- Must only depend on `hermes-crypto`.
