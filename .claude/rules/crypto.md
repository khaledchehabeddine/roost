---
paths:
  - "crates/hermes-core/**/*.rs"
  - "crates/hermes-crypto/**/*.rs"
---

# Crypto Rules

- Secret keys are always wrapped in `Zeroizing<T>` — never raw `Vec<u8>`
- Wrap decrypted output in `Zeroizing::new()` immediately — before any validation or early returns
- Secret material crossing FFI must use `Zeroizing` wrappers — public keys as `Vec<u8>` are acceptable
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Production randomness must use `OsRng` — no other RNG source outside test modules
- Encryption: XChaCha20-Poly1305
- Key exchange: X25519 · Signing: Ed25519
- Key derivation: Argon2id
- Protocol: Double Ratchet — replayed messages must be rejected, ratchet steps must follow correct sequence, expired keys must be deleted
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
