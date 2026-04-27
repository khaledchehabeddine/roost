# Protocol State Invariants

## Pattern

Protocol state machines must reject invalid transitions deterministically. For Hermes' Double Ratchet and X3DH-lite handshake, this means:

- Replays rejected (a message decrypted once cannot be decrypted again)
- Out-of-order messages handled via bounded skipped-key cache
- Expired or evicted keys deleted (forward secrecy)
- Header authentication before any state change
- Hard caps on per-chain and total skipped keys; max-age eviction

## Why it matters

Protocol-state bugs are the highest-impact class of vulnerability in messaging crypto:

- **Replay attacks** allow an attacker to resend captured messages, breaking authenticity and replay-protection guarantees
- **Out-of-order DoS** — unbounded skipped-key storage lets an attacker exhaust memory by sending forged headers with high message numbers
- **Forward secrecy violations** — failing to delete used keys means past sessions remain decryptable if device state leaks
- **Race conditions in state restoration** — concurrent message receipt or interrupted persistence can leave the ratchet in a state that re-decrypts a message

These bugs aren't catch-all "security issues" — they're protocol-specific invariants documented in the Signal/Double Ratchet spec, and missing any one of them is a known-class vulnerability.

## Hermes' Double Ratchet invariants

From `crates/hermes-crypto/src/double_ratchet.rs`:

### Hard caps

```rust
const MAX_SKIP: u32 = 100;                    // per-chain skip cap
const MAX_SKIPPED_KEYS_TOTAL: usize = 500;    // total cache cap
```

These prevent unbounded memory growth from forged or malicious traffic. An attacker cannot force the ratchet to cache more than `MAX_SKIPPED_KEYS_TOTAL` keys.

### Out-of-order receipt

`try_skipped_message_keys` is called *before* attempting a chain advance:

```rust
if let Some(plaintext) = self.try_skipped_message_keys(ciphertext, header, ad)? {
    return Ok(plaintext);
}
// ... only then advance the chain
```

This handles messages arriving out of order without advancing past them. Critically, the cache lookup happens against `(public_key, message_number)` tuples — replays against the same cache entry must be detected and rejected.

### Persisted state validation

When the ratchet state is restored from disk:

```rust
if wire.mk_skipped.len() > MAX_SKIPPED_KEYS_TOTAL {
    return Err(CryptoError::MaxSkippedKeysExceeded);
}
```

A blob whose `mk_skipped` exceeds the cap is rejected at deserialization — preventing tampered persisted state from bypassing the runtime cap.

### Header authentication before state change

Decryption verifies the AEAD tag (which authenticates the header as associated data) *before* advancing any state. A failed decryption must not:
- Advance the chain key
- Evict skipped keys
- Update the receiving DH public key

## Anti-patterns

```rust
// BAD: unbounded skipped-key storage
struct Ratchet {
    mk_skipped: HashMap<(PublicKey, u32), MessageKey>,  // no cap = DoS
}

// BAD: advance chain on decryption failure
fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, _> {
    self.chain_key = kdf_ck(&self.chain_key);  // <-- advance first
    self.cipher.decrypt(ct)?                   // <-- then try
        // failed decrypt = chain key still advanced = lost message slot
}

// BAD: accepting messages without authenticating headers
fn decrypt(&mut self, header: &Header, ct: &[u8]) -> Result<Vec<u8>, _> {
    self.update_receiving_key(header.public_key);  // <-- state change
    self.cipher.decrypt(ct, b"")                    // <-- no AAD = header unauthenticated
}

// BAD: re-decryption of cached message
fn try_skipped(&mut self, key: (PublicKey, u32)) -> Option<MessageKey> {
    self.mk_skipped.get(&key).cloned()  // <-- get without remove = replay
}
// Correct: self.mk_skipped.remove(&key)

// BAD: persisted-state cap not enforced
fn restore(blob: &[u8]) -> Result<Self, _> {
    let wire: Wire = postcard::from_bytes(blob)?;
    Ok(Self::from_wire(wire))  // <-- no cap check = bypassable runtime guard
}
```

## Apply when

- Implementing message receipt (decrypt path)
- Implementing message send (encrypt path)
- Adding new state transitions to a protocol
- Deserializing protocol state from disk or network
- Reviewing diffs that touch `crates/hermes-crypto/src/double_ratchet.rs`, `ratchet.rs`, or `handshake.rs`

## Audit checklist

Before approving protocol changes:

1. **Replays rejected** — messages cannot be decrypted twice (skipped-key cache uses `remove`, not `get`)
2. **DH ratchet ordering** — state advances *only* on successful authenticated decryption
3. **Skipped-key handling** — hard cap enforced both at runtime AND at deserialization
4. **Out-of-order receipt** — `try_skipped_message_keys` called before chain advance
5. **Replay windows** — per-chain and across DH ratchet rotations
6. **Key compromise recovery** — chain keys deleted after use; DH ratchet step rotates ephemeral keys
7. **State persistence races** — concurrent receipt path is safe (no unprotected mutation that could lose ratchet state)

## Hermes example: skipped-key overflow

From `crates/hermes-crypto/src/double_ratchet.rs:280-288` — when skipping would push the cache past `MAX_SKIPPED_KEYS_TOTAL`, the operation rejects rather than evicting:

```rust
fn skip_message_keys(&mut self, until_n: u32) -> Result<(), CryptoError> {
    if until_n > self.nr + MAX_SKIP {
        return Err(CryptoError::MaxSkipExceeded);
    }
    let keys_to_skip = (until_n - self.nr) as usize;
    if self.mk_skipped.len() + keys_to_skip > MAX_SKIPPED_KEYS_TOTAL {
        return Err(CryptoError::MaxSkippedKeysExceeded);
    }
    // ... insert keys
}
```

Why error rather than evict: the cache is `BTreeMap<([u8; 32], u32), MessageKey>` keyed by `(sender_pubkey, n)`. "Oldest" is not well-defined — `iter().next()` returns the lex-smallest *pubkey*, not the temporally-oldest entry. Evicting in that order would let an adversary who can shape traffic selectively drop a *victim sender's* cached keys (a denial-of-decryption attack). Error-on-overflow avoids this; the trade-off is that legitimate out-of-order traffic past the cap fails to decrypt and must be re-sent.

Note: AGENTS.md's `## Coding Guidelines > Crypto` rule states "drop the oldest on overflow" as the intended behavior. The current implementation is more conservative (error). If eviction is added later, it will need a time-ordered secondary index — naive `BTreeMap` iteration is unsafe.

## See also

- Signal Double Ratchet spec: <https://signal.org/docs/specifications/doubleratchet/>
- X3DH spec: <https://signal.org/docs/specifications/x3dh/>
- ADR `0005-message-cipher-selection.md` — why XChaCha20-Poly1305
- ADR `0007-x3dh-lite-handshake.md` — Hermes' X3DH variant
- AGENTS.md `## Coding Guidelines > Crypto > Protocol: Double Ratchet` — the enforceable rule
- [nonce-derivation.md](nonce-derivation.md) — message-key expansion that backs each protocol step
