# Protocol State Interface and Concurrent Instances

**Status:** Accepted

v0.5.0 protocol state crosses the public Rust API as versioned opaque blobs addressed by state kind and state key, with consumers responsible for get/set: loading each blob before an operation and durably writing the returned advanced blobs afterward. Required state kinds are ratchet/session state, prekey state, sender certificate, deduplication set, and pending acknowledgments; the library keeps no authoritative in-memory copy between operations and returns outbound Message bytes together with all advanced protocol-state updates, so consumers must linearize the full load, operation, and durable commit for a given Identity's protocol state through a critical section or conditional write that rejects stale inputs.

Outbound Message bytes must not leave local durable storage until the corresponding advanced protocol-state updates are committed atomically, for example by committing the advanced state and an outbox record in the same consumer transaction. Session replacement wipes all protocol state for that Session/Identity boundary rather than silently reinitializing selected blobs, because partial reset can desynchronize the Ratchet, prekeys, acknowledgments, or replay defenses. v0.5.0 adds explicit versioned Message and blob formats and rejects unsupported versions; it does not carry legacy support for old pre-release blobs. Before release, review the public Rust surfaces for Message encode/decode, protocol-state get/set, operation result shape, wipe, migration errors, and fixture replay.

## Scope Boundary

v0.5.0 defines persistence and concurrency contracts, including replay and deduplication state persistence. v0.6.0 owns the event stream, delivery acknowledgment, retry, and user-visible deduplication behavior built on top of those blobs.
