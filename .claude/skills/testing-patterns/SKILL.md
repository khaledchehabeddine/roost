---
name: testing-patterns
description: Apply Hermes' testing patterns when writing or reviewing tests — Known Answer Tests for crypto primitives, integration tests across crate boundaries. Use when adding tests or refactoring test layout.
allowed-tools: Read Glob Grep
paths:
  - "crates/**/*.rs"
---

# Hermes Testing Patterns

Compresses Hermes' testing conventions into routable references. Loads when test-adjacent code is in scope. Use to choose the right test shape, structure assertions, and avoid common test-rot patterns.

## Routing map

When the task involves... read this reference:

- Adding a Known Answer Test for a crypto primitive (HKDF, AEAD, signing, ratchet step) → [kat-vectors.md](../../../docs/agents/testing/kat-vectors.md)
- Writing an integration test that crosses crate or module boundaries → [integration-tests.md](../../../docs/agents/testing/integration-tests.md)

## Quick checklist

Before submitting test changes, verify:

- [ ] Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise
- [ ] Integration tests live in `crates/<crate>/tests/<scenario>.rs`, exercising only the public API
- [ ] KAT vector tests cite their derivation source (RFC, upstream library + version, or paired derivation script)
- [ ] Test inputs are deterministic — fixed timestamps, seeded RNGs (when used at all), no `SystemTime::now()` or `OsRng`
- [ ] Test data with magic bytes is named with a `KAT_*` or `EXPECTED_*` constant, not inlined as a literal at the assertion site
- [ ] No shared mutable state across tests (each test owns its `Setup`)
- [ ] `#[cfg(test)]` is the *only* place seeded RNGs or relaxed safety constraints are acceptable
