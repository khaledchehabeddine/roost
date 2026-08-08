# Tests

- Name each test for one behavior scope. Assert that behavior and its required preconditions.
- Avoid duplicate coverage at the same responsibility layer. Keep repeated coverage for security or protocol invariants and across public API, persistence, serialization, FFI, or other boundaries.
- Put inline unit tests in `#[cfg(test)] mod tests` at the bottom of the source file they exercise.
- Put one public-API scenario per `crates/<crate>/tests/<scenario>.rs`. Add a module docstring naming the scenario and crossed boundary. If an integration test needs an internal item, move it inline.
- Keep test-only crates under `[dev-dependencies]`.
- Do not derive assertions from `SystemTime::now()` or `OsRng` output. Accept them as opaque inputs and assert relative or round-trip behavior.
- Give each test its own `Setup` from `setup()`. Do not share mutable state through `static mut` or `Lazy`.

## Known-answer tests

- Prefer vector sources in this order: RFC, reference implementation, independent library, hand derivation. Flag hand-derived crypto vectors for security review.
- Never derive the expected output with the implementation under test.
- Group KATs before related behavior tests and store outputs in `<PRIMITIVE>_KAT_EXPECTED` constants.
- Put derivation notes on the test in `Source`, `Inputs`, `Derivation`, `Output` order; name the reference tool and API and use a `text` fence for pseudocode.
- Reuse the same expected constant for both directions, such as encrypt/decrypt or sign/verify.
