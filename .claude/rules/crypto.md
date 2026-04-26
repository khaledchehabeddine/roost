---
paths:
  - "crates/hermes-core/**/*.rs"
  - "crates/hermes-crypto/**/*.rs"
---

# Crypto Rules

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must use `OsRng` — no other RNG source outside test modules
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct info string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing`. Stack-locals consumed immediately by a constructor don't need wrapping.
- Wrap decrypted output in `Zeroizing::new()` immediately — before any validation or early returns
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Protocol: Double Ratchet:
  - Replayed messages must be rejected
  - Ratchet steps must follow the correct sequence
  - Expired keys must be deleted
  - Skipped message keys must have a hard cap (per chain and total) and a max age — drop the oldest on overflow
