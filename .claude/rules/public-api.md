---
paths:
  - "crates/*/src/lib.rs"
  - "crates/hermes-uniffi/**"
---

# Public API Rules

- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump
- Prefer adding a new function over breaking an existing one
- `pub` minimization — every `pub` item must have an external consumer, otherwise demote to `pub(crate)` or remove
- Internal errors crossing the FFI must convert to `HermesError` via `From` impls
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations
- Public types must follow project rustdoc guidelines — see [docs/agents/rust-docs-style.md](../../docs/agents/rust-docs-style.md)
