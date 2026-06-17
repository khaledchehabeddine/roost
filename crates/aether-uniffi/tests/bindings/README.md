# Binding Test Harness

Swift and Kotlin harnesses in this directory exercise UniFFI bindings built with the `fixture-replay` feature. They are test-only consumers of canonical fixtures and FFI-boundary regressions, not production SDK examples.

- `FixtureReplay.*`: canonical message, handshake, and protocol-state fixture replay.
- `Issue122Coverage.*`: generated API coverage for identity, backup, protocol-state store,
  sessions, messages, contacts/blocking, events, delivery retry, prekey replenishment, and negative
  binding-visible errors.
- `SecureStorageUnexpectedError.*`: foreign storage exception mapping and mutex recovery.

Run through `scripts/test/binding-fixture-replay.sh`.
