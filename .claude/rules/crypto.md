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
