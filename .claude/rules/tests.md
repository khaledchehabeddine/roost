---
paths:
  - "crates/**/*.rs"
---

# Tests Rules

- Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise — not in a sibling `tests.rs` module
- Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the public API
- One scenario per integration test file — split rather than grow into mega-files
- KAT vector tests cite their derivation source (RFC, upstream library + version, or paired derivation script) in a doc comment alongside the expected constant
- KAT expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`) — never inlined as literals at the assertion site
- Test inputs are deterministic — fixed timestamps (`const FIXED_TS: u64 = ...`) or fixed byte arrays. No `SystemTime::now()` or `OsRng` in test paths. See `crates/hermes-crypto/tests/session.rs` for the established pattern
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`
- Test-only dependencies live under `[dev-dependencies]` in Cargo.toml — never `[dependencies]`
