# UDL vs Proc-Macro Mode

## Hermes uses proc-macro

From `crates/hermes-uniffi/src/lib.rs`:

```rust
uniffi::setup_scaffolding!("hermes");

#[uniffi::export]
pub fn generate_signing_key_pair() -> SigningKeyPair { ... }

#[derive(uniffi::Object)]
pub struct InMemorySecureStorage { ... }
```

The Rust definition IS the FFI definition — no `.udl` file, no duplication. Renaming a function updates the FFI automatically. The compiler catches FFI-incompatible types at the export site.

## When UDL is the better choice

Stick with proc-macro for almost everything. UDL becomes worth it only when:

- Multi-language teams review the FFI surface and need a single readable contract
- A non-UniFFI consumer needs the interface description as input
- Explicit FFI versioning matters more than refactor ergonomics

For Hermes' current scope (single contributor, all-Rust, only UniFFI consumers), proc-macro is unambiguously right.

## Don't mix modes

UniFFI supports mixing UDL and proc-macros in the same crate. Don't — split definitions across two locations is harder to reason about. One mode per crate.

## Scaffolding names are load-bearing

```rust
uniffi::setup_scaffolding!("hermes");  // matches [lib] name in Cargo.toml
```

```toml
# uniffi.toml
[bindings.kotlin]
package_name = "com.relay.hermes"

[bindings.swift]
module_name = "Hermes"
```

These appear in every consumer's `import` statement. Treat them as binary-stable — changing requires coordinating with all client codebases.

## See also

- UniFFI proc-macro docs: <https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html>
- [type-bridges.md](type-bridges.md) — what types are FFI-compatible
- [error-boundary.md](error-boundary.md) — error type rules
