# Protocol State Interface and Concurrent Instances

**Status:** Accepted

Protocol state crosses the public Rust API as versioned opaque blobs addressed by state kind and state key, with consumers responsible for get/set: loading each blob before an operation and durably writing the returned advanced blobs afterward. Ratchet/session blobs carry the Double Ratchet state and may bind the expected peer sender identity key for post-decryption sealed-sender checks. Required state kinds are ratchet/session state, prekey state, sender certificate, deduplication set, and pending acknowledgments; the library keeps no authoritative in-memory copy between operations and returns outbound Message bytes together with all advanced protocol-state updates, so consumers must linearize the full load, operation, and durable commit for a given Identity's protocol state through a critical section or conditional write that rejects stale inputs.

Outbound Message bytes must not leave local durable storage until the corresponding advanced protocol-state updates are committed atomically, for example by committing the advanced state and an outbox record in the same consumer transaction. Session replacement wipes all protocol state for that Session/Identity boundary rather than silently reinitializing selected blobs, because partial reset can desynchronize the Ratchet, prekeys, acknowledgments, or replay defenses. Message and blob formats reject unsupported versions; within the current envelope, session and contact bodies decode the current shape first and fall back to the immediately prior body shape, a bounded pre-release exception recorded in [the protocol-state blob versioning ADR](../../crates/aether-core/docs/adr/0007-protocol-state-blob-versioning.md). Before release, review the public Rust surfaces for Message encode/decode, protocol-state get/set, operation result shape, wipe, decode errors, and fixture replay.

## Scope Boundary

This decision defines persistence and concurrency contracts, including replay and deduplication state persistence. Event streams, delivery acknowledgment, retry, and user-visible deduplication behavior sit above these blobs.
