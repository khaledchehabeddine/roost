# Cryptographic Test Vector Derivation

**Date:** 2026-04-22
**Status:** Accepted

## Decision

Test vectors for the Double Ratchet primitives are computed using external reference tools (pyca/cryptography, libsodium) that share no code with the RustCrypto crates used in production. The resulting byte values are committed as constants next to each test, with a doc comment recording the inputs, algorithm, and tool family used. The derivation script itself is not committed.

## Why

- Signal does not publish official Double Ratchet test vectors, so the values have to be derived somewhere
- Committing the derivation script would create a path of the least resistance for auditors: running it produces a clear pass without the reviewer exercising independent judgment, so omitting it forces each auditor to bring their own derivation tool
- Because the derivation tools and RustCrypto share no code, the tests passing means three independent implementations of the primitives all agree — not that the code agrees with itself
- Doc comments describe the derivation in terms of the primitive's RFC, so auditors can re-derive values using any tool they already trust
- Same inline-test structure as libsignal, with added derivation documentation that libsignal omits
- Regeneration after a parameter change is rare — Double Ratchet info strings and AEAD parameters rotate only on protocol version bumps
