# Constant-Time Comparison

## Pattern

Compare secret material (MACs, signatures, key bytes, tokens, hashes) using a constant-time equality check. The check's runtime must not depend on *where* the bytes differ — only on the input lengths.

In Hermes: use `subtle::ConstantTimeEq::ct_eq`.

## Why it matters

`==` on byte slices short-circuits at the first differing byte; comparison time leaks the secret one byte at a time (the basis of padding-oracle and MAC-validation attacks). Constant-time comparison runs the same operations regardless of input contents — the side channel is closed.

## Apply when

- Validating an HMAC or signature against an expected value
- Comparing a derived public key against an expected one (X25519 prekey verification)
- Checking a session token, capability, or authentication tag
- Equality on any value derived from secret key material

## Don't apply when

- Comparing public values that don't depend on secrets (lengths, version bytes, public keys *of attacker's choosing*)
- Branching on a value the attacker already controls (no information to leak)

## Hermes example

From `crates/hermes-crypto/src/handshake.rs:78-84` — sanity-checking that the envelope's signed-prekey reference matches the local SPK before deriving the shared secret:

```rust
use subtle::ConstantTimeEq;

let spk_ref_matches: bool = envelope
    .responder_spk_ref
    .ct_eq(spk.public().as_bytes())
    .into();
if !spk_ref_matches {
    return Err(CryptoError::HandshakeSpkMismatch);
}
```

Note: both sides of this comparison are *public* values (the envelope's wire byte string and a local public key). Constant-time isn't strictly required here — this is conservative usage. The pattern still matters: it makes `==` vs `ct_eq` a reliable lint signal, so any future secret-vs-secret comparison reads consistently.

Note also: `ct_eq` returns `subtle::Choice` (a wrapped `u8`), not `bool`. The `.into()` conversion is also constant-time. Don't be tempted to convert with `.unwrap_u8() == 1` — that re-introduces the branch.

## Anti-pattern

```rust
// BAD: short-circuits on first differing byte; PartialEq on Vec<u8> has the same issue
if mac == expected_mac { ... }
```

## Verification

Audit with:

```bash
grep -rn "==" crates/hermes-crypto/src/ | grep -v "//\|test\|len()\|0\|1\|2\|3"
```

Inspect each remaining `==` — is either side derived from secret material? If yes, switch to `ct_eq`.

## See also

- `subtle` crate documentation: <https://docs.rs/subtle/>
- AGENTS.md `## Coding Guidelines > Crypto` — the enforceable rule
- [zeroization.md](zeroization.md) — managing the lifetime of the secrets you're comparing
