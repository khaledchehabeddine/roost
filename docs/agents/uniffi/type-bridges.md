# UniFFI Type Bridges

## Pattern

Choose types at the FFI boundary that UniFFI can represent in both Swift and Kotlin without lossy translation. Wrap FFI-incompatible internal types within `hermes-uniffi` — never expose them directly.

## Why it matters

UniFFI generates bindings for both Swift and Kotlin from the same Rust signatures. Each language has different type-system constraints, and UniFFI translates conservatively:

- **Primitives** (`u8`, `u32`, `i64`, `bool`, `f64`) — direct mapping, free
- **`String`** — UTF-8, allocated on each call
- **`Vec<u8>`** — byte array, copied across the boundary
- **`Option<T>`** — nullable in Swift/Kotlin
- **`Vec<T>`** — list/array in client languages
- **`Arc<T>` where `T: uniffi::Object`** — reference-counted handle to a Rust-managed object
- **Records** (structs with `#[derive(uniffi::Record)]`) — value types, all fields FFI-compatible
- **Errors** (`#[derive(uniffi::Error)]`) — typed enum errors

What UniFFI does NOT support (these must be wrapped):

- `Zeroizing<T>` — Rust-only wrapper; bytes pass as `Vec<u8>`, then the Rust side wraps after load
- Lifetimes (`&str`, `&[u8]`) — only owned types cross
- Trait objects (`Box<dyn Trait>`) without `#[uniffi::export(with_foreign)]`
- Custom types from external crates without UniFFI derives (e.g., `chrono::DateTime`, `uuid::Uuid` need conversion)
- Tuples — use a Record instead

## Hermes patterns

### Objects: `Arc<Mutex<Inner>>` for shared state

```rust
#[derive(uniffi::Object)]
pub struct InMemorySecureStorage {
    inner: Mutex<hermes_core::InMemorySecureStorage>,
}

#[uniffi::export]
impl InMemorySecureStorage {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self { inner: Mutex::new(hermes_core::InMemorySecureStorage::new()) }
    }
}
```

`#[derive(uniffi::Object)]` creates an opaque handle. The Swift/Kotlin side gets a class that holds an `Arc` to the Rust side. The `Mutex` provides interior mutability — required because UniFFI methods take `&self`.

### Foreign-implementable traits: `#[uniffi::export(with_foreign)]`

```rust
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError>;
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;
    fn delete(&self, key: String) -> Result<(), HermesError>;
}
```

Allows Swift/Kotlin to *implement* the trait (e.g., a Swift `Keychain`-backed `SecureStorage` impl is passed to Rust). Constraints:

- `Send + Sync` required (Rust may call from any thread)
- All method signatures must use FFI-representable types
- `&self` is the only allowed receiver (no `&mut self`, no `self`)

### Byte arrays: `Vec<u8>` not `Zeroizing<Vec<u8>>`

UniFFI doesn't know about `Zeroizing`. The pattern:

```rust
// At the FFI boundary: bare Vec<u8>
fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;

// On the Rust side, immediately after load: wrap
let bytes = self.storage.load(key)?;  // Vec<u8>
let secret = bytes.map(Zeroizing::new); // Zeroizing<Vec<u8>>
```

The doc comment in `crates/hermes-uniffi/src/lib.rs` for `SecureStorage` makes this explicit:

> `value` and `load` return bare `Vec<u8>` because UniFFI does not support `Zeroizing`. The `SecureStorageAdapter` wraps loaded values in `Zeroizing` on the Rust side.

This is the canonical "wrap on the Rust side" pattern for any secret material crossing the FFI.

### Records vs Objects

| Use a Record (`#[derive(uniffi::Record)]`) when | Use an Object (`#[derive(uniffi::Object)]`) when |
|---|---|
| Value-type semantics (cheap to copy) | Has identity / shared state |
| All fields are FFI-representable directly | Holds resources (locks, file handles) |
| Immutable after construction | Has methods that mutate |
| Bindings can `==` compare structurally | Reference equality matters |

Hermes uses Objects for `InMemorySecureStorage`, `KeyStore`, etc. — they hold mutable state behind `Mutex`. A bundle of public bytes (e.g., `PreKeyBundle` if exposed) would be a Record.

## Anti-patterns

```rust
// BAD: Zeroizing or borrowed types cross FFI (won't compile)
#[uniffi::export] fn get_secret(&self) -> Zeroizing<Vec<u8>> { ... }
#[uniffi::export] fn name(&self) -> &str { ... }

// BAD: leaking internal Rust type as Object — FFI clients break when internals change.
// Wrap with a thin FFI-stable surface that only exposes the operations clients need.
#[derive(uniffi::Object)]
pub struct RatchetState(hermes_crypto::RatchetState);
```

## Wrapping FFI-incompatible internal types

The Hermes-specific rule says: *FFI-incompatible core types must be wrapped within the `hermes-uniffi` crate.*

Pattern:

```rust
// hermes-crypto: internal Rust type — may change freely
pub struct RatchetState { /* lots of internal fields, may change */ }

// hermes-uniffi: stable FFI surface
#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<hermes_crypto::RatchetState>,
}

#[uniffi::export]
impl Session {
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, HermesError> {
        let mut state = self.inner.lock().unwrap();
        state.encrypt(&plaintext).map_err(Into::into)
    }
}
```

The wrapper:
- Decouples internal type evolution from FFI surface stability
- Provides the `Mutex` for thread safety (UniFFI methods must be `&self`-callable)
- Centralizes error conversion via `Into::into` (`From<CryptoError> for HermesError`)

## See also

- AGENTS.md `## Coding Guidelines > UniFFI` — the enforceable rule
- [error-boundary.md](error-boundary.md) — what error types are allowed in `Result<T, E>`
- [async-patterns.md](async-patterns.md) — additional constraints on async functions
- UniFFI book on types: <https://mozilla.github.io/uniffi-rs/latest/types/index.html>
