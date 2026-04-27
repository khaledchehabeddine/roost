---
name: kat-vector
description: Trigger when adding a Known Answer Test vector for a cryptographic primitive in Hermes — derive expected output from an authoritative source, pin as a constant, write the paired test. Not for general unit tests or property-based tests.
---

## Steps

### 1. Identify the primitive

Ask the user which primitive (e.g., "HKDF expand", "AEAD encrypt", "Ed25519 sign", "ratchet step") if not provided.

### 2. Locate the implementation

Run `grep -rn "<primitive>" crates/hermes-crypto/src/` to find the function or test module to add the KAT to.

### 3. Identify the derivation source

Confirm with the user before proceeding. Preference order:

- **RFC test vectors** (e.g., RFC 5869 Appendix A for HKDF-SHA256)
- **Reference implementation** (libsodium via `pynacl`, BoringSSL, pyca/cryptography)
- **Independent Rust crate** (different from the one under test)
- **Hand-derived from spec** (last resort; flag for security-auditor review)

### 4. Choose fixed inputs

Use minimal, easy-to-re-derive inputs (e.g., `key = [0u8; 32]`, empty associated data, short plaintext). Document them in a doc comment alongside the expected constant.

### 5. Derive the expected output

- Write or update a Python derivation script at `scripts/kat-derive/<primitive>.py`
- Run it; capture the hex output
- Add a doc comment in the test file citing the script path and library version

### 6. Add the test

In `crates/hermes-crypto/src/<module>.rs` under `#[cfg(test)] mod tests`:

- Define the expected constant: `const <PRIMITIVE>_KAT_EXPECTED: [u8; N] = [...]`
- Write the test function: `#[test] fn <primitive>_known_answer() { ... }`
- Doc comment cites inputs, derivation source, expected constant

### 7. Pair the directions if applicable

If the primitive has paired directions (encrypt/decrypt), add a paired KAT using the SAME expected constant — proves round-trip consistency.

### 8. Run the test

`cargo test --package hermes-crypto <primitive>_known_answer` — confirm it passes.

### 9. Handle failure

If the test fails, the implementation diverges from the reference. Investigate with the user — do NOT modify the expected constant to match the implementation.

## See also

- `docs/agents/testing/kat-vectors.md` — KAT design rationale and examples
- `docs/agents/crypto/` — primitive-specific patterns
- ADR `0008-cryptographic-test-vector-derivation.md`
