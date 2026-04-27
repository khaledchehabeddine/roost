# Memory Zeroization for Secrets

## Pattern

Scrub secret bytes from memory when they're no longer needed. The compiler may leave copies in registers, stack frames, or heap allocations long after the variable goes out of scope; the OS may swap pages to disk. Zeroization makes secret recovery from process memory significantly harder.

In Hermes: `zeroize::Zeroizing<T>` for heap-allocated secrets; `#[derive(ZeroizeOnDrop)]` on custom secret-bearing types; immediate wrapping at the boundary where secret material first appears.

## Why it matters

Rust's allocator doesn't scrub freed memory, so secret bytes can persist on the heap long after `drop` — recoverable via core dump, swap-out, or memory inspector. Zeroization writes zeros before the bytes are freed, with compiler fences to prevent dead-store elimination. Closes the largest exposure window (long-lived heap residue); doesn't address registers or intermediate copies.

## Three Hermes-specific patterns

### 1. Wrap heap secrets in `Zeroizing<T>`

For `Vec<u8>`, `[u8; N]`, or any byte container holding secrets:

```rust
use zeroize::Zeroizing;

pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(self.secret_key.to_bytes())
}
```

`Zeroizing<T>` is a transparent wrapper that calls `T::zeroize()` on drop. It implements `Deref` so call sites use it transparently.

### 2. `#[derive(Zeroize, ZeroizeOnDrop)]` on secret-bearing structs

For custom types that hold secrets alongside other fields. From `crates/hermes-crypto/src/signed_prekey.rs:17-26`:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use ed25519_dalek::Signature;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    secret_key: StaticSecret,    // implements Zeroize via x25519-dalek's "zeroize" feature
    #[zeroize(skip)]
    public_key: PublicKey,       // not secret — skip
    #[zeroize(skip)]
    signature: Signature,        // ed25519_dalek::Signature does NOT impl Zeroize — skip is required for the derive to compile
    #[zeroize(skip)]
    created_at: u64,             // not secret — skip
}
```

Two reasons `#[zeroize(skip)]` shows up:
1. **The field is not secret** (public_key, created_at) — scrubbing is unnecessary
2. **The field's type doesn't impl Zeroize** (signature) — required to make the `#[derive(Zeroize)]` compile

Both reasons appear in this struct. The `Signature` case is the load-bearing one — without `#[zeroize(skip)]`, the derive fails.

### 3. Wrap decrypted output immediately

Wrap *before* validation or early returns:

```rust
fn decrypt(...) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let plaintext = Zeroizing::new(
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?
    );
    // any further validation happens AFTER wrapping;
    // if validation fails, plaintext is still scrubbed on drop
    validate(&plaintext)?;
    Ok(plaintext)
}
```

Wrapping after validation creates a window where the unwrapped plaintext can leak via early-return panic or unwind.

## Apply when

- A function returns secret material to a caller (return `Zeroizing<T>`)
- A struct holds secret bytes among non-secret fields (`#[derive(ZeroizeOnDrop)]` + `#[zeroize(skip)]`)
- Decryption produces plaintext (wrap immediately)
- A buffer holds secret material across an `await` or `?` (especially error path)

## Don't apply when

- Stack-local values consumed by a constructor in the same function (e.g., bytes that move directly into a `StaticSecret::random_from_rng` call) — no heap residue to scrub
- Public values: keys, signatures, hashes of attacker-known values

## Anti-patterns

```rust
// BAD: secret as plain Vec — heap residue persists
fn derive_key() -> Vec<u8> {
    let mut k = vec![0u8; 32];
    fill(&mut k);
    k  // dropped without scrubbing
}

// BAD: validation before wrap — early-return panic leaks plaintext
fn decrypt(...) -> Result<Vec<u8>, _> {
    let plaintext = cipher.decrypt(...)?;       // unwrapped
    validate(&plaintext)?;                       // panic here = leak
    Ok(Zeroizing::new(plaintext).into())        // wrapping too late
}
```

## Hermes-specific rule

Types holding secret material must NOT derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop`. Add a comment explaining why when an exception is needed.

## Verification

Audit secret-bearing types:

```bash
grep -rn "secret\|key" crates/hermes-crypto/src/ | grep -E "(struct|enum)" | head -20
```

For each secret-bearing type, confirm:
1. `ZeroizeOnDrop` derived (or wrapped externally)
2. No `Clone`/`Debug`/`Serialize` (or paired with `ZeroizeOnDrop`)
3. Non-secret fields marked `#[zeroize(skip)]`

## See also

- `zeroize` crate documentation: <https://docs.rs/zeroize/>
- AGENTS.md `## Coding Guidelines > Crypto` — the enforceable rule
- [randomness.md](randomness.md) — generating fresh secrets that need zeroization
