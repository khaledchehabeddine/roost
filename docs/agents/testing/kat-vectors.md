# Known Answer Tests (KATs)

## Pattern

A Known Answer Test verifies a cryptographic primitive against a precomputed expected output. Inputs are fixed; the output is derived once from an authoritative source (RFC, reference implementation, or independent library) and pinned as a constant.

In Hermes: KATs guard every crypto primitive — HKDF expansion, AEAD encrypt/decrypt, ratchet steps, message-key expansion. They are the single most important defense against silent crypto regressions.

## Why it matters

Cryptographic correctness is unfalsifiable from positive testing alone — an encrypt/decrypt round-trip succeeds even when both directions are wrong in the same way. KATs anchor the implementation to an independent ground truth; if a KAT breaks, either the implementation or its spec interpretation changed, and that warrants explicit review.

## Structure

A KAT pattern in practice:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Inputs: `mk = MessageKey([0; 32])`, `caller_ad = []`, `header.dh_pub_key = [0; 32]`.
    ///
    /// Expected ciphertext: derived independently using libsodium's
    /// `crypto_aead_xchacha20poly1305_ietf_encrypt` (via pyca/cryptography 46) — deliberately a
    /// different implementation than the RustCrypto `chacha20poly1305` crate under test.
    ///
    /// The decrypt direction has a paired KAT at [`aead_decrypt_known_answer`].
    #[test]
    fn aead_encrypt_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let header = Header {
            dh_pub_key: PublicKey::from([0u8; 32]),
            // ...
        };
        let ciphertext = aead_encrypt(&mk, b"", &header, b"hello").unwrap();
        assert_eq!(ciphertext.as_slice(), &AEAD_KAT_EXPECTED_CIPHERTEXT);
    }

    /// The libsodium-reference ciphertext for the fixed AEAD KAT inputs.
    ///
    /// Referenced by both [`aead_encrypt_known_answer`] and [`aead_decrypt_known_answer`], so the
    /// two directions test against the same fixed value.
    const AEAD_KAT_EXPECTED_CIPHERTEXT: [u8; 44] = [
        // hex bytes, hand-derived...
    ];
}
```

Three things make this a good KAT:

1. Doc comment cites the derivation source — not just "libsodium" but the specific function call. A reviewer can re-derive independently.
2. Same expected constant used by both directions (encrypt + decrypt) — proves round-trip consistency *and* spec conformance simultaneously.
3. Inputs are minimal and fixed — `[0u8; 32]` keys, empty AD, short plaintext. Easy to re-derive by hand.

## Apply when

- Adding any new crypto primitive (HKDF call, AEAD operation, signature, KDF chain step)
- Modifying an existing primitive (verify the change is intentional, not a regression)
- Implementing a protocol step (one KAT per step direction)

## Don't apply when

- Testing protocol-level orchestration (use integration tests for that — KATs are for primitives)
- Testing error paths (KAT inputs should always succeed; error tests are separate)
- Testing performance characteristics (KATs verify *what*, not *how fast*)

## Choosing a derivation source

Trustworthy sources, in order of preference:

1. RFC test vectors (e.g., RFC 5869 appendix A for HKDF, RFC 8439 for ChaCha20-Poly1305). These are normative — if your output doesn't match, you're wrong by definition.
2. Reference implementation outputs (libsodium, BoringSSL, OpenSSL). Trusted because they're widely deployed and audited.
3. Independent Rust crate output (pyca/cryptography from Python, also widely audited). Acceptable when no RFC vectors exist.
4. Hand-derived from spec (last resort, requires careful review).

Avoid: deriving the KAT by running your own implementation. That tests "the implementation matches itself," which is a tautology.

## Writing the derivation script

Always pair a KAT with a script that re-derives the expected output. Hermes pattern:

- Python script (using `cryptography` or `pynacl`) that reads the same inputs, runs the equivalent operation, prints hex output
- Doc comment in the test cites which script and library version derived the constant
- Script lives in `scripts/kat-derive/` (or similar) so future regeneration is mechanical

Example doc comment:

```rust
/// Expected values derived with pyca/cryptography 46 (HKDF-SHA256).
///
/// Re-derive: `python3 scripts/kat-derive/expand_message_key.py`
```

## Anti-patterns

```rust
// BAD: assertion derived from the implementation under test
#[test]
fn round_trip() {
    let ct = encrypt(&key, &nonce, b"hello");
    let pt = decrypt(&key, &nonce, &ct);
    assert_eq!(pt, b"hello");
    // Both encrypt and decrypt could be wrong in the same way (e.g., wrong nonce
    // length) and this still passes.
}

// BAD: expected value with no provenance
const EXPECTED: [u8; 32] = [/* magic bytes, where from? */];

// BAD: multiple unrelated assertions in one KAT
#[test]
fn aead_kat() {
    assert_eq!(encrypt(...), expected1);    // KAT 1
    assert_eq!(hkdf(...), expected2);       // unrelated KAT 2
    assert_eq!(sign(...), expected3);       // unrelated KAT 3
    // failure here doesn't tell you which primitive regressed
}
```

## Verification

Audit Hermes' KAT coverage:

```bash
grep -rn "known_answer\|_kat\|KAT" crates/hermes-crypto/src/ | grep -E "(fn|const)" | head -20
```

For each primitive in `crates/hermes-crypto/src/`, verify there is at least one KAT that:
- Has a doc comment citing the derivation source
- Uses fixed minimal inputs
- Pins the expected output as a named constant

## See also

- `kat-vector` workflow skill — guided creation of a new KAT
- AGENTS.md `## Coding Guidelines > Tests` — enforceable rules
- [integration-tests.md](integration-tests.md) — when testing primitive composition rather than primitives
- ADR `0008-cryptographic-test-vector-derivation.md` — Hermes' decision on KAT derivation strategy
