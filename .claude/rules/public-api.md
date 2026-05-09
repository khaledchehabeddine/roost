---
paths:
  - "crates/*/src/**/*.rs"
---

# Public API Rules

- Modules are organizational, not public-API boundaries
- `pub` minimization — every `pub` item needs an out-of-crate user (a `pub use` at `lib.rs` doesn't count)
- Secret-bearing types additionally require a consumer who specifically needs the secret form
- Acronym tolerance scales with proximity to consumers, tightest at the FFI boundary:
  - `#[uniffi::export]` (T1): none except universal (`URL`, `HTTP`, `JSON`); all crypto terms spelled out (`signed_prekey`, not `spk`)
  - Cross-crate `pub` (T2): industry-standard primitives only (`KDF`, `AEAD`, `HKDF`, `MAC`); no protocol-internal acronyms (`SPK`, `OPK`, `IK`)
  - `pub(crate)` (T3): protocol shorthand fine (`spk`, `ik`, `ek`, `dh`, `ad`)
  - Function-local: anything readable in context
- Public types must follow project rustdoc guidelines — see [docs/agents/rust-docs-style.md](../../docs/agents/rust-docs-style.md)
- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump
