# Testing

Broken code can still round-trip data and reject bad input, so a round trip or an error alone doesn't prove it works.

## Scope

- Add a test only when no existing test covers an important app flow, a costly failure, or a likely regression.
- Test what a caller can observe, such as outputs, errors, and stored state.

## Names

- Name each test for the behavior it checks, such as `decode_example_rejects_unknown_version`, not `test_decode`.

## Assertions

- In tests, use `unwrap` on a call that should succeed, not `?`, since a panic reports its line.
- Assert the exact error, such as `matches!(result, Err(ExampleError::UnknownVersion))`, not `result.is_err()`.
- When a failure must leave state unchanged, assert that it did, such as by comparing a value read before and after the call.
- For each key derivation, signature, and hash Roost produces, test that changing any one input changes its output.
