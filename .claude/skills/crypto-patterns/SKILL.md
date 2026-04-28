---
name: crypto-patterns
description: Apply Hermes' cryptographic patterns when reading or writing crypto code — constant-time comparison, AEAD nonce derivation, zeroization, randomness, and protocol state invariants. Use when working on crates/hermes-crypto or anywhere secret material is handled.
allowed-tools: Read Glob Grep
paths:
  - "crates/hermes-crypto/**/*.rs"
  - "crates/hermes-core/**/*.rs"
---

# Hermes Crypto Patterns

Compresses Hermes' recurring crypto patterns into routable references. Loads when crypto code is in scope. Use to verify correctness, recognize anti-patterns, and apply the right primitive choice.

## Routing map

When the task involves... read this reference:

- Comparing secret material (MACs, keys, hashes, tokens) → [constant-time.md](../../../docs/agents/crypto/constant-time.md)
- Deriving AEAD nonces, KDF info strings, domain separation → [nonce-derivation.md](../../../docs/agents/crypto/nonce-derivation.md)
- Holding, dropping, or moving secret bytes → [zeroization.md](../../../docs/agents/crypto/zeroization.md)
- Choosing or invoking a random number generator → [randomness.md](../../../docs/agents/crypto/randomness.md)
- Implementing or modifying protocol state machines (Double Ratchet, X3DH-lite) → [protocol-state.md](../../../docs/agents/crypto/protocol-state.md)

## Quick checklist

Before submitting crypto changes, verify:

- [ ] Secret comparisons use `subtle::ConstantTimeEq`, never `==`
- [ ] AEAD nonces derived alongside message keys via HKDF (not random under a long-lived key)
- [ ] Every HKDF call uses a distinct info string for domain separation
- [ ] Heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values wrapped in `Zeroizing`
- [ ] Decrypted output wrapped in `Zeroizing::new()` *before* validation or early returns
- [ ] No `Clone`/`Debug`/`Serialize` on secret-bearing types unless `ZeroizeOnDrop` is also derived
- [ ] Production randomness uses `OsRng` — no other RNG source outside test modules
- [ ] Collections sized by external input (`HashMap`, `Vec`) have a hard cap constant
- [ ] Skipped message keys: per-chain cap, total cap — reject on overflow (no eviction)
- [ ] Replays rejected; out-of-order receipt deterministic

For depth on any item, load the matching reference.
