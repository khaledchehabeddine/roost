# Test scope and limits

Tests protect concrete consumer failures. Crypto owns handshake agreement, ratchet advancement,
replay and skipped-key bounds. Its short generated bidirectional traces cover combinations of
ordering and direction without maintaining a separate fuzz project. Fixed signed-prekey and
certificate answers pin exact bytes. The canonical evidence and handshake fixtures remain shared
where several boundaries consume them.

Core tests cover accepted-message production, identity and prekey lifecycle, stale-write rejection,
atomic blob/outbox updates, corruption faults, contact trust and recovery after ambiguous storage
replies. Setup fills a skipped-key cache directly when the test only needs Core's overflow behavior.
Server owns evidence-verifier rejection cases. Client tests retain handwritten conversion and
error decisions; straightforward forwarding does not need another protocol suite.

Swift and Kotlin package tests live in their distribution repositories. They load the actual
package, cross a foreign storage callback, recover a lost write reply and preserve binary binding
bytes. Swift CryptoKit verifies both the canonical evidence transcript and a fresh
signature returned through the bindings. Kotlin compares the returned evidence fields with the
canonical fixture. Canonical fixture bytes are copied from the selected
Roost revision during the check, with no maintained native copy.

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
