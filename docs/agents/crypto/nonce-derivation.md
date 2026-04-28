# AEAD Nonce Derivation and HKDF Domain Separation

## Pattern

Derive AEAD nonces *alongside* message keys via HKDF — never sample randomly under a long-lived key. Every HKDF call uses a distinct `info` string for domain separation.

In Hermes: `XChaCha20-Poly1305` with 24-byte `XNonce`, derived via `HKDF-SHA256` from a per-message `MessageKey`.

## Why it matters

Nonce reuse under the same key is total break for ChaCha20-Poly1305 (and AES-GCM): keystream XOR-cancels and the auth key can be recovered. Random nonces under a long-lived key risk collision; derived nonces eliminate the risk by tying the (key, nonce) pair to a per-message message key that is never reused.

Domain separation: HKDF calls with the same IKM but different `info` strings produce uncorrelated outputs. Reusing `info` across unrelated derivations means an attacker who learns one purpose's output can compute the other. Each call site needs a distinct `info`. Examples in Hermes: `b"HermesX3DHLite"` (handshake.rs), `RK_INFO = b"HermesRatchet_RK"` (ratchet.rs), `HKDF_MK_INFO = b"HermesRatchet_MK"` (message-key expansion in double_ratchet.rs).

## Implementation

Message-key expansion derives both key and nonce in a single HKDF call:

```rust
/// Expands a message key into a 32-byte encryption key and 24-byte nonce via HKDF-SHA256.
fn expand_message_key(mk: &MessageKey) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, mk.as_bytes());
    let mut okm = Zeroizing::new([0u8; 56]);
    hkdf.expand(HKDF_MK_INFO, okm.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 24];
    enc_key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..56]);
    Ok((enc_key, nonce))
}
```

Both `okm` and `enc_key` are wrapped in `Zeroizing` — they hold secret AEAD key material. The nonce stays plain because it isn't secret.

This pattern guarantees:
1. The message key is single-use (advanced after every message)
2. The (enc_key, nonce) pair is fully determined by the message key
3. No nonce is ever sampled or reused

## Apply when

- Encrypting any message (always derive, never sample)
- Computing per-session keys from a master secret (use `info` to separate purposes)
- Splitting one HKDF output into multiple derived values (single call, distinct byte ranges)

## Anti-patterns

```rust
// BAD: random nonce under long-lived key
let nonce = rand::random::<[u8; 24]>();
cipher.encrypt(XNonce::from_slice(&nonce), payload)?;

// BAD: same info for unrelated derivations (or empty info — no domain separation)
let enc_key = hkdf_expand(&secret, b"key", 32);
let mac_key = hkdf_expand(&secret, b"key", 32);  // collision
```

## Verification

Audit HKDF call sites:

```bash
grep -rn "Hkdf::<Sha256>::new\|hkdf::Hkdf" crates/hermes-crypto/src/
```

For each call, confirm:
1. `info` argument is non-empty
2. `info` is unique to that call site (search the rest of the codebase)
3. Output is consumed by *one* purpose (or split deterministically across purposes)

Audit nonce sources:

```bash
grep -rn "XNonce::from_slice\|Nonce::from_slice" crates/hermes-crypto/src/
```

Confirm the byte source is HKDF output, not RNG.

## See also

- HKDF spec: RFC 5869
- ChaCha20-Poly1305 spec: RFC 8439
- XChaCha extension: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>
- [protocol-state.md](protocol-state.md) — message-key lifecycle in Double Ratchet
