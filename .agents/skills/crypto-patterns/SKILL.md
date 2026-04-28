---
name: crypto-patterns
description: Trigger when reading or writing cryptographic code in Hermes — comparing secret material, deriving keys or nonces, zeroizing memory, choosing an RNG, or modifying protocol state machines (Double Ratchet, X3DH-lite). Not for non-crypto Rust review or general code style.
---

# Hermes Crypto Patterns

Compresses Hermes' recurring crypto patterns into routable references. Use to verify correctness, recognize anti-patterns, and apply the right primitive choice.

## Routing map

When the task involves... read this reference:

- Comparing secret material (MACs, keys, hashes, tokens) → [constant-time.md](../../../docs/agents/crypto/constant-time.md)
- Deriving AEAD nonces, KDF info strings, domain separation → [nonce-derivation.md](../../../docs/agents/crypto/nonce-derivation.md)
- Holding, dropping, or moving secret bytes → [zeroization.md](../../../docs/agents/crypto/zeroization.md)
- Choosing or invoking a random number generator → [randomness.md](../../../docs/agents/crypto/randomness.md)
- Implementing or modifying protocol state machines (Double Ratchet, X3DH-lite) → [protocol-state.md](../../../docs/agents/crypto/protocol-state.md)

## Quick checklist

Before submitting crypto changes, verify:

- Secret comparisons use `subtle::ConstantTimeEq`, never `==`
- AEAD nonces derived alongside message keys via HKDF (not random under a long-lived key)
- Every HKDF call uses a distinct info string for domain separation
- Heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values wrapped in `Zeroizing`
- Decrypted output wrapped in `Zeroizing::new()` *before* validation or early returns
- No `Clone`/`Debug`/`Serialize` on secret-bearing types unless `ZeroizeOnDrop` is also derived
- Production randomness uses `OsRng` — no other RNG source outside test modules
- Collections sized by external input have a hard cap constant
- Skipped message keys: per-chain cap, total cap — reject on overflow (no eviction)
- Replays rejected; out-of-order receipt deterministic

For depth on any item, read the matching reference.
