# Integration Tests

## Pattern

Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the *public API* of the crate, the way a downstream consumer would. They cover scenarios that cross module boundaries, validate composed behavior, and catch breaks in the API surface.

Inline unit tests (`#[cfg(test)] mod tests { ... }`) test internal logic. Integration tests test the contract.

Canonical pattern: two `RatchetState` instances bootstrapped via X3DH-lite exchange messages back and forth.

## Why it matters

Unit tests miss two important classes of bugs:

1. API surface regressions — a refactor that changes a public type signature breaks downstream consumers. Inline tests use internals so they don't catch this. Integration tests do.
2. Cross-module composition bugs — module A and module B each work in isolation, but their composition is wrong. Inline tests of A and B both pass; the bug only appears when they're orchestrated together.

Integration tests treat the crate as a black box, which is the only way to verify the box is well-shaped.

## Structure

Three things to include in any new integration test:

1. Module-level docstring states the test file's purpose — what scenario, what crosses what boundary
2. `use hermes_crypto::{...}` imports public names only — if a test needs an internal item, that's a smell (move the test inline, or surface the item)
3. `Setup` struct + `setup()` function as the shared fixture — tests own their state via `setup()`; no global mutable state. Use `const FIXED_TS: u64 = 1_700_000_000;` for any timestamp input.

## Apply when

- Verifying that a public type's lifecycle works end-to-end (create → use → drop)
- Testing scenarios where multiple modules cooperate (handshake + ratchet, key store + identity)
- Checking that downstream consumers can compose the public API without surprises
- Regression-testing a bug that only appeared under realistic usage

## Don't apply when

- Testing one function in isolation (use inline `#[cfg(test)] mod tests`)
- Testing internal helpers (use inline; integration tests can't see private items)
- Testing crypto primitives against expected outputs (use KAT — see [kat-vectors.md](kat-vectors.md))

## File organization

Hermes' convention:

```
crates/hermes-crypto/
  src/
    double_ratchet.rs           # contains #[cfg(test)] mod tests for unit tests
    handshake.rs                # same
  tests/
    session.rs                  # integration: handshake + ratchet end-to-end
    persistence.rs              # integration: state save/restore round-trip
    key_compromise.rs           # integration: post-compromise security scenarios
```

One file per scenario. Avoid mega-files like `tests/integration.rs` that test everything — they grow unmanageable.

## Determinism

Integration tests are particularly prone to flakiness because they exercise more state. Hermes' patterns:

- Fixed timestamps: `const FIXED_TS: u64 = 1_700_000_000;` — never `SystemTime::now()`
- Setup struct: each test calls `setup()` and gets fresh state; no `static mut`, no `Lazy<>`
- Deterministic key generation in setup is acceptable *within a test file* — but each test should call `setup()` independently, not share results across tests

When a test absolutely needs ordering (e.g., "send 3 messages then crash, restore, deliver out-of-order"), make the ordering explicit in the test body — don't depend on cross-test ordering.

## Anti-patterns

```rust
// BAD: integration test using internal items
use hermes_crypto::double_ratchet::__internal_advance_chain;  // <-- private
#[test]
fn my_test() { __internal_advance_chain(...); }
// If you need this, the API surface needs widening OR move the test inline.

// BAD: shared mutable state
static SHARED: Lazy<Mutex<Setup>> = Lazy::new(|| Mutex::new(setup()));
#[test] fn a() { SHARED.lock().mutate(); }
#[test] fn b() { /* depends on a()'s mutation */ }
// Test order is not guaranteed in Rust.

// BAD: SystemTime::now() in tests
#[test]
fn timestamp_test() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Test passes today, fails in 6 years when assumptions about `now`'s value break.
}

// BAD: monolithic integration test
// tests/integration.rs — 2000 lines covering handshake, ratchet, persistence, errors, ...
// Split into one file per scenario.
```

## Verification

Audit Hermes' integration test layout:

```bash
ls crates/*/tests/ 2>/dev/null
```

For each integration test file, verify:
1. Module docstring states the scenario
2. Imports are public-only (no `pub(crate)` items)
3. Has a `Setup` struct + `setup()` function (or equivalent fresh-state pattern)
4. Tests use `FIXED_TS` or similar deterministic constants

## See also

- AGENTS.md `## Coding Guidelines > Tests` — enforceable rules
- [kat-vectors.md](kat-vectors.md) — for testing primitives, not compositions
