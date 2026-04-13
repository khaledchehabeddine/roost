---
paths:
  - "crates/hermes-core/**/*.rs"
  - "crates/hermes-crypto/**/*.rs"
---

# Crypto Rules

- Encryption: XChaCha20-Poly1305
- Key exchange: X25519 · Signing: Ed25519
- Key derivation: Argon2id
- Secret keys are always wrapped in `Zeroizing<T>` — never raw `Vec<u8>`
- Secret material crossing FFI must use `Zeroizing` wrappers — public keys as `Vec<u8>` are acceptable
- Production randomness must use `OsRng` — no other RNG source outside test modules
- Protocol: Double Ratchet — replayed messages must be rejected, ratchet steps must follow correct sequence, expired keys must be deleted
