---
paths:
  - "crates/**/*.rs"
---

# Tests Rules

- Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise
- Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the public API; if a test needs an internal item, the test belongs inline
- One scenario per integration test file
- Module docstring on integration tests states the scenario and what crosses what boundary
- Test-only dependencies live under `[dev-dependencies]` in Cargo.toml
- Test assertions must not depend on `SystemTime::now()` or `OsRng` outputs — both may be opaque inputs (e.g., relative timestamps, round-trip keys)
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`
