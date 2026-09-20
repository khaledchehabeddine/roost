# Testing

Use the repository's [verification policy](../../../../../AGENTS.md#verification) to decide whether coverage is needed. Test the behavior at the layer that owns it; add coverage at another layer only when that boundary introduces a distinct risk.

- Prioritize consumer happy paths and consequential failures in public APIs, FFI, persistence, serialization, and security or protocol state.
- Test names state the behavior being protected. Assertions prove that behavior and its necessary preconditions.
- In tests, `unwrap` setup that can fail; use `expect` when its message says which precondition broke.
- Simple forwarding, fixed values, and implementation details need no separate tests when existing coverage or tooling already protects the relevant contract.
- Unit tests live in `#[cfg(test)] mod tests` at the bottom of the owning source file. Integration tests live in `crates/<crate>/tests/<scenario>.rs` and use only the public API.
- Keep each integration test file focused on one scenario. Start it with one `//!` line naming the boundary it crosses; `missing_docs` requires crate docs, and the file name already gives the scenario.
- Put test-only dependencies under `[dev-dependencies]`. Reuse existing fixtures where helpful without introducing a shared framework for unrelated tests.
- Each test owns its mutable state. Assertions must not depend on the current time or random outputs; these may be opaque inputs to relative-time or round-trip checks.

## Known-Answer Tests

- Derive each expected output outside Roost: RFC vectors first, then a reference implementation, an independent library, or a hand derivation checked independently. A value computed with Roost's own code is a regression pin, not a known-answer test; name it that way.
- Comment each test with its source (tool, version, and API call), inputs, derivation, and output, so anyone can re-derive the value. Write derivation pseudocode in a `text` block.
- Keep expected outputs in named constants (`<PRIMITIVE>_KAT_EXPECTED`), and check both directions (encrypt and decrypt, sign and verify) against the same constant.
