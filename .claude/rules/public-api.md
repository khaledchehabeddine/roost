---
paths:
  - "crates/*/src/lib.rs"
  - "crates/hermes-uniffi/**"
---

# Public API Rules

- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump — affects Swift/Kotlin bindings
- Prefer adding a new function over breaking an existing one
- `pub` minimization — every `pub` item must have an external consumer (another crate, the FFI surface, or a documented public re-export). `pub` items with no consumer are dead code; demote to `pub(crate)` or remove
- FFI-exposed APIs (`#[uniffi::export]`, `#[derive(uniffi::*)]`) require corresponding `From<InternalError> for HermesError` impls within `hermes-uniffi` for every error type they can return
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations
- Public types must have rustdoc per `docs/agents/rust-docs/style.md` tier (T1 for `hermes-uniffi`, T2 for other crates)
