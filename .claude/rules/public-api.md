---
paths:
  - "crates/*/src/lib.rs"
  - "crates/hermes-uniffi/**"
---

# Public API Rules

## Surface

- Modules are organizational, not public-API boundaries
- `pub` minimization — every `pub` item needs an out-of-crate user (a `pub use` at `lib.rs` doesn't count)
- Secret-bearing types must not be reachable from `pub` accessors without an out-of-crate consumer who specifically needs the secret form. Bundle-returning facades demote secret-returning helpers
- Public types must follow project rustdoc guidelines — see [docs/agents/rust-docs-style.md](../../docs/agents/rust-docs-style.md)

## Naming scope ladder

Acronym tolerance scales with proximity to consumers, tightest at the FFI boundary:

| Scope | Acronyms allowed | Vocabulary source |
|---|---|---|
| `#[uniffi::export]` (T1) | None except universal (`URL`, `HTTP`, `JSON`). All crypto terms spelled out (`signed_prekey`, not `spk`) | Consumer mental model |
| Cross-crate `pub` (T2) | Industry-standard primitives only (`KDF`, `AEAD`, `HKDF`, `MAC`). No protocol-internal acronyms (`SPK`, `OPK`, `IK`). Match FFI vocabulary | Same as T1 |
| `pub(crate)` (T3) | Conventional in the field is fine (`spk`, `ik`, `ek`, `dh`, `ad`) | Protocol/spec shorthand |
| Function-local | Anything readable in context | Ad hoc |

## Stability and breaks

- Prefer adding a new function over breaking an existing one
- Pre-1.0 breaks are fine but every public-symbol change must be enumerated in the PR description / release notes: type renames, method renames, field renames, parameter renames, return-type changes, visibility demotions
- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump — affects Swift/Kotlin bindings

## FFI

- Internal errors crossing the FFI must convert to `HermesError` via `From` impls
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations
