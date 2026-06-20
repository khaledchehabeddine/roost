# Protocol State Interface and Concurrent Instances

**Status:** Accepted

Protocol state crosses the public Rust API as versioned opaque blobs addressed by state kind and state key, with consumers responsible for get/set: loading each blob before an operation and durably writing the returned advanced blobs afterward. Ratchet/session blobs carry the Double Ratchet state and may bind the expected peer sender identity key for post-decryption sealed-sender checks. Current decoded blob bodies are ratchet/session state, deduplication set, pending acknowledgments, and contact state; PreKey State remains KeyStore secure-storage state, and Sender Certificates are caller validation inputs rather than decoded Protocol State Blob bodies. `PreKey` and `SenderCertificate` remain reserved public protocol-state kinds for API and FFI stability and wipe/delete handling; they have no current decoded blob body. The library keeps no authoritative in-memory copy between operations and returns outbound Message bytes together with all advanced protocol-state updates. Consumers must protect Protocol State Blobs at rest with confidentiality and integrity controls comparable to identity-key storage, must keep commits atomic, durable, and crash-consistent, and must linearize the full load, operation, and durable commit for a given Identity's protocol state through a critical section or conditional write that rejects stale inputs.

Outbound Message bytes must not leave local durable storage until the corresponding advanced protocol-state updates are committed atomically, for example by committing the advanced state and an outbox record in the same consumer transaction. Session replacement wipes all protocol state for that Session/Identity boundary rather than silently reinitializing selected blobs, because partial reset can desynchronize the Ratchet, prekeys, acknowledgments, or replay defenses. Message and blob formats reject unsupported major versions; same-major body compatibility is explicit, bounded, and fixture-backed as recorded in [the protocol-state blob versioning ADR](../../crates/aether-core/docs/adr/0007-protocol-state-blob-versioning.md).

## Scope Boundary

This decision defines persistence and concurrency contracts, including replay and deduplication state persistence. Event streams, delivery acknowledgment, retry, and user-visible deduplication behavior sit above these blobs.

## Verification Evidence

- `docs/protocol-state-invariant-tests.md` records generated traces, stale-commit rejection, rollback, corruption, and recovery scenarios for the host-serialized mutation model.
- `crates/aether-core/tests/fixtures/protocol_state_blobs_v1.md` records current blob kinds, `1.0` fixture coverage, unsupported-version rejection, and opaque consumer storage expectations.
