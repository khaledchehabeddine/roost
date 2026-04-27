---
name: kat-vector
description: Add a Known Answer Test vector for a cryptographic primitive — derive expected output from an authoritative source (RFC, libsodium, pyca/cryptography), pin as a constant, write the paired test. Use when adding a new primitive or guarding an existing one against regression.
argument-hint: [primitive-name]
disable-model-invocation: true
allowed-tools: Bash(python3 *) Bash(cargo test *) Bash(grep *) Edit Read Write
---

Add a Known Answer Test vector:

1. Identify the primitive: `$ARGUMENTS` if provided, otherwise ask the user (e.g., "HKDF expand", "AEAD encrypt", "Ed25519 sign", "ratchet step")
2. Locate the implementation: grep `crates/hermes-crypto/src/` for the primitive's function or test module
3. Identify the derivation source — confirm with the user before proceeding:
   - **RFC test vectors** (preferred when available — e.g., RFC 5869 Appendix A for HKDF-SHA256)
   - **Reference implementation** (libsodium via `pynacl`, BoringSSL, or pyca/cryptography)
   - **Independent Rust crate** (different from the one under test)
   - **Hand-derived from spec** (last resort; flag for security-auditor review)
4. Choose minimal fixed inputs (e.g., `key = [0u8; 32]`, empty associated data, short plaintext). Document the inputs in a doc comment alongside the expected constant
5. Derive the expected output:
   - Write a Python derivation script at `scripts/kat-derive/<primitive>.py` (or update an existing one)
   - Run it; capture the hex output
   - Add a doc comment in the test file citing the script path and library version
6. Add the test in `crates/hermes-crypto/src/<module>.rs` under `#[cfg(test)] mod tests`:
   - Define the expected constant: `const <PRIMITIVE>_KAT_EXPECTED: [u8; N] = [...]`
   - Write the test function: `#[test] fn <primitive>_known_answer() { ... }`
   - Doc comment cites the inputs, the derivation source, and the expected constant
7. If the primitive has paired directions (encrypt/decrypt), add a paired KAT that uses the SAME expected constant — proves round-trip consistency
8. Run the test: `cargo test --package hermes-crypto <primitive>_known_answer` — confirm it passes
9. If the test fails, the implementation diverges from the reference. Investigate with the user — do NOT modify the expected constant to match the implementation

Verify alignment with `docs/agents/testing/kat-vectors.md` and `docs/agents/crypto/` references.
