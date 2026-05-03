---
paths:
  - "crates/hermes-uniffi/**"
---

# UniFFI Rules

- FFI-incompatible core types must be wrapped in this crate — `&str`, `&[u8]`, lifetimes, trait objects without `#[uniffi::export(with_foreign)]`, tuples, external-crate types without conversion
- Secret bytes cross as bare `Vec<u8>` and wrap in `Zeroizing` immediately in the adapter layer, not client code
- Stateful types wrap with `#[derive(uniffi::Object)]` and interior mutability — decouples internal type evolution from FFI stability
- Foreign-implementable traits use `#[uniffi::export(with_foreign)]` to let clients implement Rust-callable traits
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate
- Internal errors convert to `HermesError` via `From` impls
- `HermesError` variants describe failures in client-relevant terms (e.g., `AlreadyExists`, `NotFound`)
- Internal failures the client cannot meaningfully handle (e.g., lock poisoning, KDF output overflow) reduce to a generic `InternalError { reason: String }` — `reason` is for logs, not client logic
