# Binding Test Harness

Swift and Kotlin harnesses in this directory exercise UniFFI bindings built with the `fixture-replay` feature. They are test-only consumers of canonical fixtures and FFI-boundary regressions, not production SDK examples.

- `FixtureReplay.*`: canonical message, handshake, and protocol-state fixture replay.
- `Issue122Coverage.*`: generated API coverage for identity, backup, protocol-state store,
  sessions, messages, contacts/blocking, events, delivery retry, prekey replenishment, and negative
  binding-visible errors.
- `Issue219PreparedOperations.*`: generated prepared-operation lifecycle coverage for provisional
  outputs, stable identifiers, orphan recovery, idempotent transitions, recovery gating, and stale
  SecureStorage preconditions.
- `Issue124PackageConsumerTests.swift`: generated iOS Swift Package consumer coverage, run through
  `scripts/test/ios-package-consumer.sh`.
- `SecureStorageUnexpectedError.*`: foreign storage exception mapping and mutex recovery.
- `AuthenticationTranscriptSigning.*`: bare identity-key signing over a caller-built
  authentication transcript, verified with the platform's own Ed25519 rather than Aether's, plus
  the reserved-prefix refusals.
- `Issue122Coverage.*` also covers `initiatorIdentityHint`: the stranger path, where the sender is
  read from the frame and `prepareAcceptSession` is then called with no expected identity.
- `KeyBindingVerification.*`: standalone IK/DK binding verification, with the platform's own Ed25519
  as the counterparty rather than Aether's, plus the context-separation and malformed-input refusals.
- `EvidenceBundleVectors.*`: version-one accepted-Message evidence replay through the production
  verifier, including malformed, profile, version, signature, and cross-relay replay refusals.
  CryptoKit and the JDK independently verify both signatures carried by the vector.

Run through `scripts/test/binding-fixture-replay.sh`.
