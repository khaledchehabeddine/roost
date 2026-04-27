# UniFFI Error Boundary

## Pattern

Errors crossing the FFI boundary must derive `uniffi::Error`. Library errors from `hermes-core` and `hermes-crypto` are converted to a single FFI-shaped error type (`HermesError`) via `From` impls. Panics never cross the boundary — every `#[uniffi::export]` call must return `Result<T, HermesError>` for any fallible operation.

## Why it matters

UniFFI's binding generators (Swift, Kotlin) cannot represent arbitrary Rust types. They require:

- Errors with a stable, FFI-representable shape (typed enum variants)
- No panics — a Rust panic at the FFI boundary aborts the host process (Swift/Kotlin can't catch it)
- No leaked internal types — domain errors specific to `hermes-core` shouldn't appear in Swift/Kotlin code

A single `HermesError` enum funnels every fallible operation into one client-visible shape. Variants describe *what went wrong* in client-relevant terms (`AlreadyExists`, `NotFound`, `DecryptionFailed`), not internal implementation details (`LockPoisoned`, `HkdfExpand`).

## Hermes structure

From `crates/hermes-uniffi/src/lib.rs`:

```rust
/// Errors surfaced across the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    AlreadyExists,
    BackupFailed { reason: String },
    Corrupt,
    DecryptionFailed,
    InternalError { reason: String },
    InvalidData { reason: String },
    NotFound,
    Storage { reason: String },
}

impl std::fmt::Display for HermesError { /* ... */ }
impl std::error::Error for HermesError {}
```

Conversion from internal errors:

```rust
impl From<IdentityError> for HermesError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => HermesError::AlreadyExists,
            IdentityError::BackupFailed(reason) => HermesError::BackupFailed { reason },
            // Lock poisoning is internal — reduce it to InternalError
            IdentityError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            // ...
        }
    }
}
```

Three patterns to notice:

1. **Variants are client-meaningful** — `AlreadyExists`, `NotFound` map to error states the client app needs to handle differently
2. **Internal failures get `InternalError { reason }`** — lock poisoning, clock skew, programmer errors. The client doesn't branch on these; it logs and surfaces a generic failure.
3. **`From` impls live in `lib.rs`** — single conversion table. Adding a new internal error variant means adding one `From` arm.

## Hermes-specific rule

> Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate.

## Apply when

- Adding a new `#[uniffi::export]` function or method
- Adding a new internal error variant in `hermes-core`/`hermes-crypto` (must add corresponding `From` arm)
- Designing a new error category that the client needs to handle distinctly

## Anti-patterns

```rust
// BAD: panic crossing the boundary — host process abort
#[uniffi::export]
pub fn decrypt(&self, ct: Vec<u8>) -> Vec<u8> {
    self.cipher.decrypt(&ct).unwrap()
}

// BAD: leaking internal error type to clients (StorageError is hermes-core internal)
#[uniffi::export]
pub fn store(&self, key: String, value: Vec<u8>) -> Result<(), StorageError> {
    self.inner.store(key, value)
}
```

## The "no library errors" rule

Internal library errors that the client cannot meaningfully handle must be reduced to a generic `InternalError { reason }` variant. The `reason` string is for logs/debugging, not for client logic.

Examples:

| Internal failure | Maps to |
|---|---|
| `LockPoisoned` (programmer error) | `InternalError { reason: "internal lock poisoned" }` |
| `Clock` (system clock before epoch — impossible-ish) | `InternalError { reason: "system clock before Unix epoch" }` |
| `HkdfExpand` (HKDF output overflow — impossible with valid inputs) | `InternalError { reason: ... }` |

The client app's response to all of these is the same: log it, show a generic error. So one variant suffices.

## Verification

Audit FFI boundary:

```bash
grep -rn "#\[uniffi::export" crates/hermes-uniffi/src/
```

For each export, verify:
1. Return type is `T` (infallible) or `Result<T, HermesError>`
2. No `.unwrap()` or `.expect()` in the body
3. Internal errors converted via `?` (which uses the `From` impls)

Audit the conversion table:

```bash
grep -rn "impl From<.*> for HermesError" crates/hermes-uniffi/src/
```

For every error type that can appear in an export's `?` chain, there must be a `From` impl. Compiler enforces this — but adding the export without the `From` is a quick way to discover gaps.

## See also

- AGENTS.md `## Coding Guidelines > UniFFI` — the enforceable rule
- AGENTS.md `## Coding Guidelines > Error Handling` — domain error type conventions
- [type-bridges.md](type-bridges.md) — what types CAN appear in `HermesError` variants
- UniFFI book on error handling: <https://mozilla.github.io/uniffi-rs/latest/types/errors.html>
