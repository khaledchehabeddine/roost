# Testing

Use the repository's [verification policy](../../../../../AGENTS.md#verification) to decide whether coverage is needed. Test the behavior at the layer that owns it; add coverage at another layer only when that boundary introduces a distinct risk.

- Prioritize consumer happy paths and consequential failures in public APIs, FFI, persistence, serialization, and security or protocol state.
- Test names state the behavior being protected. Assertions prove that behavior and its necessary preconditions.
- Simple forwarding, fixed values, and implementation details need no separate tests when existing coverage or tooling already protects the relevant contract.
- Unit tests live in `#[cfg(test)] mod tests` at the bottom of the owning source file. Integration tests live in `crates/<crate>/tests/<scenario>.rs` and use only the public API.
- Keep each integration file focused on a scenario; its module documentation briefly identifies the behavior and boundary under test.
- Put test-only dependencies under `[dev-dependencies]`. Reuse existing fixtures where helpful without introducing a shared framework for unrelated tests.
- Each test owns its mutable state. Assertions must not depend on the current time or random outputs; these may be opaque inputs to relative-time or round-trip checks.

## Known-answer tests

- Derivation source preference: RFC vectors → reference implementation → independent crate/library → hand-derived with independent verification
- Expected outputs must never be derived against the implementation under test
- Test functions are grouped together within the file, before related non-KAT behavior tests
- Expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`)
- Derivation comment goes on the test, not the constant
- Test comments follow `Source` → `Inputs` → `Derivation` → `Output` (`Source` line names the reference tool and API call (e.g., `pyca/cryptography 46 HKDF-SHA256`))
- Derivation pseudocode uses `text` code fences
- Both directions (encrypt/decrypt, sign/verify) reference the same expected constant
