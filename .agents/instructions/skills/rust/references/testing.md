# Testing

Broken code can still round-trip data and reject bad input, so a round trip or an error alone doesn't prove it works.

## Scope

- Add or keep a test only when it catches a costly failure or likely regression that nothing else would.
- Test what a caller can observe, such as outputs, errors, and stored state.

## Placement

- Write unit tests for a module's own logic in a `#[cfg(test)]` module in the same file.
- Write integration tests for flows that span modules in `tests/integration/`.

## Names

- Name each test for the behavior it checks, such as `decode_example_rejects_unknown_version`, not `test_decode`.

## Assertions

- In tests, use `unwrap` on a call that should succeed, not `?`, since a panic reports its line.
- Assert the exact error, such as `matches!(result, Err(ExampleError::UnknownVersion))`, not `result.is_err()`.
- When a failure must leave state unchanged, assert that it did, such as by comparing a value read before and after the call.
- For each key derivation, signature, and hash Roost produces, test that changing any one input changes its output.
