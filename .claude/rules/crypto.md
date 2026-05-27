---
paths:
  - "crates/aether-core/**/*.rs"
  - "crates/aether-crypto/**/*.rs"
---

# Crypto Rules

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must come from the OS CSPRNG — `OsRng` or `getrandom`. No `thread_rng()`, seeded, or non-cryptographic RNGs outside test modules
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct, non-empty `info` string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing` immediately — before validation or early returns. Stack-locals consumed immediately by a constructor don't need wrapping
- Custom secret-bearing structs derive `Zeroize, ZeroizeOnDrop`. Mark fields with `#[zeroize(skip)]` if they are non-secret or if the field's type doesn't impl `Zeroize` (e.g., `ed25519_dalek::Signature`)
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, keys, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Protocol invariants (Double Ratchet, X3DH-lite): replay rejection, ratchet ordering, key expiration, skipped-key caps — see [docs/agents/crypto-protocol-state.md](../../docs/agents/crypto-protocol-state.md) for detail
