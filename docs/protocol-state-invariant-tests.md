# Test scope and limits

Tests protect current consumer behavior. Crypto covers handshake agreement, ratchet advancement,
replay rejection and skipped-key bounds. Short generated bidirectional exchanges cover ordering and
direction; independent cryptographic known answers stay beside the code they exercise.

Core covers identity and prekey lifecycle, contact trust, accepted-message evidence, stale writes,
atomic blob/outbox commits, corruption faults and recovery after ambiguous storage replies. It
creates Messages and state during tests. Server verifies a local signed report and builds malformed
or tampered inputs in the test. There is no stored transcript replay or format-freezing JSON suite.

Swift and Kotlin package tests live in their distribution repositories. They load the actual
package, cross a foreign storage callback, recover a lost write reply and preserve binary binding
bytes. Each keeps its small Evidence Bundle input beside the assertions, avoiding shared resource
loading and copy steps. Swift CryptoKit verifies the reconstructed Message Transcript and a fresh
signature; Kotlin checks the returned fields. The expected Evidence Identity comes from an
independent BLAKE3 C 1.7.0 calculation. A format change requires updating these local examples.

The pre-MVP tests do not promise compatibility with earlier prerelease bytes. Once real persisted
user data must survive upgrades, add focused tests for the specific supported formats. The v0.15.0
published release records and artifacts remain unchanged.

Accepted limits:

- No maintained fuzzing, Miri, sanitizer or allocation/latency budget suite. Unanticipated malformed
  inputs and platform-specific memory faults have less automated exploration. Explicit malformed,
  oversized, tampered and replay cases remain.
- No complete protocol suite repeated in each generated language, no mobile check on every Rust
  edit, and one runtime device per platform. Other shipped ABIs are built; Android package assembly
  compares their embedded native libraries with the build outputs.
- The API 36 test image cannot import Ed25519 public keys for independent Java verification.
  That check remains in Swift; Kotlin has no separate native signature oracle or fresh-signature
  oracle. Adding a crypto provider solely for tests would expand the dependency and setup cost.
- Host-store tests use a test implementation. They do not prove the consuming app's database
  isolation, crash durability or secure storage behavior.
- No coverage percentage target or formal certification claim. Independent security/code review is
  the v1 audit target. A new regression gets a focused test where its behavior is owned.
