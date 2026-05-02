---
paths:
  - "crates/*/src/lib.rs"
  - "crates/hermes-uniffi/**"
---

# Public API Rules

- Modules are organizational, not public-API boundaries
- `pub` minimization — every `pub` item needs an out-of-crate user (a `pub use` at `lib.rs` doesn't count)
- Public types must follow project rustdoc guidelines — see [docs/agents/rust-docs-style.md](../../docs/agents/rust-docs-style.md)
- Prefer adding a new function over breaking an existing one
- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump
- Internal errors crossing the FFI must convert to `HermesError` via `From` impls
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations
