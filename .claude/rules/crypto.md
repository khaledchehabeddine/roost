---
paths:
  - "crates/hermes-crypto/**"
  - "crates/hermes-core/**"
---

- Encryption: XChaCha20-Poly1305 (NOT AES-256-GCM)
- Key exchange: X25519 · Signing: Ed25519
- Key derivation: Argon2id
- Secret keys are always wrapped in `Zeroizing<T>` — never raw `Vec<u8>`
