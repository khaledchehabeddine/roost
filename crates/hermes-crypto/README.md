# hermes-crypto

Cryptographic primitives. Provides X25519 key exchange and Ed25519 signing.

## Overview

This crate wraps two key pairs — `KeyPair` (X25519, for Diffie-Hellman key agreement) and `SigningKeyPair` (Ed25519, for digital signatures). Secret keys are private fields to ensure zeroize-on-drop fires at the correct memory location; callers access secrets only through `to_secret_bytes()` and `to_signing_bytes()`, which return `Zeroizing<[u8; 32]>`.

## Dependencies

- [`ed25519-dalek`](https://github.com/dalek-cryptography/ed25519-dalek) — Ed25519 signing
- [`x25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) — X25519 key exchange
- `rand` — OS-level CSPRNG for key generation
- `zeroize` — scrubs secret key material from memory-on-drop

## Constraints

- Must not depend on any other `hermes-*` crate.
