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
- Test inputs are deterministic — no `SystemTime::now()` or `OsRng` in test paths
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`
- KAT vector tests cite the specific function call (e.g., `pyca/cryptography 46 HKDF-SHA256`) in a doc comment alongside the expected constant
- KAT expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`); both directions (encrypt/decrypt, sign/verify) reference the same constant
- KAT derivation source preference: RFC vectors → reference implementation → independent crate/library → hand-derived (flag for security-auditor review)
- KAT expected outputs must never be derived against the implementation under test
