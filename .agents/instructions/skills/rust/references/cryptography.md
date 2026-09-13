# Cryptography

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must come from the OS CSPRNG — `OsRng` or `getrandom`. No `thread_rng()`, seeded, or non-cryptographic RNGs outside test modules
- Hardcoded secret keys, seeds, and nonces are restricted to test fixtures.
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct, non-empty `info` string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing` immediately — before validation or early returns. Stack-locals consumed immediately by a constructor don't need wrapping
- Custom secret-bearing structs derive `Zeroize, ZeroizeOnDrop`. Mark fields with `#[zeroize(skip)]` if they are non-secret or if the field's type doesn't impl `Zeroize` (e.g., `ed25519_dalek::Signature`)
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, keys, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Validate lengths, formats, and bounds at network, decoding, and FFI boundaries. Bound externally driven allocations, loops, and recursion.

## Protocol state

Double Ratchet and X3DH must reject invalid transitions deterministically:

- **Replays rejected**: skipped-key cache uses `remove` on hit (consuming the key), restoring the entry if decrypt fails. Consume prevents replay; the restore prevents an attacker from burning legitimate keys via replays with tampered ciphertext
- **Out-of-order receipt**: try the skipped-key cache before advancing the chain, otherwise out-of-order messages destroy the state needed to decrypt them
- **Forward secrecy**: old chain keys overwritten by KDF advance. Consumed skipped keys are removed from the cache, otherwise leaked device state decrypts past sessions
- **State changes only on successful decrypt**: a decrypt path mutates a clone and replaces `self` only after AEAD verification succeeds (which authenticates the header as AAD). Forged headers can't mutate live state
- **Hard caps, deterministic rejection**: `MAX_SKIP` rejects large per-chain gaps; `MAX_SKIPPED_KEYS_TOTAL` bounds the total skipped-key cache. Runtime overflow rejects the message before mutating live state, and deserialization rejects oversized persisted state
