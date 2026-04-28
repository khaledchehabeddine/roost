---
name: uniffi-patterns
description: Apply Hermes' UniFFI patterns when designing or modifying the FFI surface — error wrapping at the boundary, type bridges (Vec<u8>, Arc, primitives), foreign-implementable traits, proc-macro mode. Use when working in crates/hermes-uniffi.
allowed-tools: Read Glob Grep
paths:
  - "crates/hermes-uniffi/**"
---

# Hermes UniFFI Patterns

Compresses Hermes' FFI design patterns into routable references. Loads when working on the `hermes-uniffi` crate. Use when adding or modifying APIs exposed to Swift and Kotlin clients.

## Routing map

When the task involves... read this reference:

- Defining or modifying error types crossing the FFI (panics, error derives, `From` chains) → [error-boundary.md](../../../docs/agents/uniffi/error-boundary.md)
- Choosing types at the FFI boundary (`Vec<u8>` vs `Arc<T>`, primitives, custom types) → [type-bridges.md](../../../docs/agents/uniffi/type-bridges.md)
- Choosing between UDL and proc-macro modes (Hermes uses proc-macro — when does UDL win) → [udl-vs-proc-macro.md](../../../docs/agents/uniffi/udl-vs-proc-macro.md)

## Quick checklist

Before submitting FFI changes, verify:

- [ ] Errors crossing the boundary derive `uniffi::Error` (no library errors or panics propagate)
- [ ] Domain errors from `hermes-core` and `hermes-crypto` are converted via `From` impls in `crates/hermes-uniffi/src/lib.rs`
- [ ] No `unwrap()`/`expect()` in `#[uniffi::export]` paths — every fallible call returns `Result<T, HermesError>`
- [ ] FFI-incompatible core types (e.g., `KeyPair`, `RatchetState`) are wrapped within `hermes-uniffi`
- [ ] Foreign-implementable traits (`#[uniffi::export(with_foreign)]`) require `Send + Sync` bounds
- [ ] Objects (`#[derive(uniffi::Object)]`) use `Arc<Mutex<T>>` or similar for interior mutability
- [ ] Byte arrays cross as `Vec<u8>` — wrap in `Zeroizing` on the Rust side after load
- [ ] No `Zeroizing<T>` at the boundary — UniFFI doesn't support it
- [ ] Bindings module names are stable: `module_name = "Hermes"` (Swift), `package_name = "com.relay.hermes"` (Kotlin)
