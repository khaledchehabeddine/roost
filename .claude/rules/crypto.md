---
paths:
  - "crates/hermes-core/**/*.rs"
  - "crates/hermes-crypto/**/*.rs"
---

# Crypto Rules

- Protocol: Double Ratchet — replayed messages must be rejected, ratchet steps must follow correct sequence, expired keys must be deleted
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Comparisons of MACs, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- `Zeroizing` wrapping: required for heap secrets (`Vec<u8>`, decrypted output) and FFI boundaries — not needed for stack-local values consumed immediately by a constructor
- Wrap decrypted output in `Zeroizing::new()` immediately — before any validation or early returns
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Production randomness must use `OsRng` — no other RNG source outside test modules
- Encryption: XChaCha20-Poly1305 · Key exchange: X25519 · Signing: Ed25519 · Key derivation: Argon2id
