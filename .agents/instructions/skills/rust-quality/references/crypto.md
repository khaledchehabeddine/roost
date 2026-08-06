# Crypto

- Use XChaCha20-Poly1305 for encryption, X25519 for key exchange, Ed25519 for signing, and Argon2id for passphrase key derivation.
- Source production randomness from the OS CSPRNG through `OsRng` or `getrandom`. Keep seeded and non-cryptographic RNGs inside test modules.
- Derive an AEAD nonce beside its message key through HKDF; never choose a random nonce under a long-lived key.
- Give every HKDF use a distinct, non-empty `info` value for domain separation.
- Wrap heap secrets and FFI secret values in `Zeroizing` immediately, before validation or early returns. Stack values consumed immediately by constructors need no wrapper.
- Derive `Zeroize, ZeroizeOnDrop` for custom secret-bearing structs. Mark non-secret or non-`Zeroize` fields with `#[zeroize(skip)]`.
- Do not derive `Clone`, `Debug`, or `Serialize` for a secret-bearing type unless it also derives `ZeroizeOnDrop`; explain the exceptional need in a comment.
- Compare MACs, keys, tokens, and hashes with `subtle::ConstantTimeEq`, never `==`.
- Give every collection sized by external input a hard cap constant.
- For Double Ratchet or X3DH state, also read `docs/agents/crypto-protocol-state.md`. Preserve replay rejection, skipped-key ordering and caps, expiration, forward secrecy, and commit-on-authenticated-success.
