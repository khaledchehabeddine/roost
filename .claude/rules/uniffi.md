---
paths:
  - "crates/hermes-uniffi/**"
---

# UniFFI Rules

- FFI-incompatible core types must be wrapped within this crate. Common cases: `&str`, `&[u8]`, lifetimes, trait objects without `#[uniffi::export(with_foreign)]`, tuples, external-crate types without conversion
- Stateful types wrap with `#[derive(uniffi::Object)]` and interior mutability — decouples internal type evolution from FFI stability
- Foreign-implementable traits use `#[uniffi::export(with_foreign)]` to let clients implement Rust-callable traits
- Secret bytes cross the FFI as bare `Vec<u8>` and wrap in `Zeroizing` immediately on the Rust side — wrapping happens in the adapter layer, not in client code
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate
- `HermesError` variants describe failures in client-relevant terms (e.g., `AlreadyExists`, `NotFound`). Internal failures the client cannot meaningfully handle (e.g., lock poisoning, KDF output overflow) reduce to a generic `InternalError { reason: String }` — the `reason` is for logs, not for client logic
