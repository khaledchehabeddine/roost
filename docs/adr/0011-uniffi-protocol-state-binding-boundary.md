# UniFFI Protocol-State Binding Boundary

**Status:** Accepted

The UniFFI API exposes protocol-state persistence as opaque blobs addressed by Protocol State Kind
and key. Host apps provide durable load and commit behavior for those blobs; Rust remains
authoritative for every protocol transition and returns the complete set of state updates together
with any produced Message, Acknowledgment Artifact, Event, retry instruction, or recovery signal.
Generated Swift and Kotlin bindings are artifacts of the Rust UniFFI surface, not checked-in SDK
source, so the binding layer stays type-safe and free of handwritten FFI code.

Binding callers must commit returned updates atomically with any output they surface or enqueue.
Mutation methods do not auto-commit into host storage, because the host owns the transaction that
may also include outbox rows, contact views, or retry scheduling metadata. Protocol State Blobs
remain byte-opaque across the boundary; Swift and Kotlin may store, replace, or delete them by
address, but they never inspect ratchet, deduplication, pending-acknowledgment, or contact-state
payloads.

Each `ProtocolStateUpdate` carries a binding-level commit check. New-state updates require the
address to be absent, snapshot-derived updates carry the digest of the blob Rust loaded, and wipe
updates are explicitly unchecked. Host commits must enforce those checks inside the same durable
transaction as the replacement/delete. This prevents stale concurrent ratchet commits from silently
overwriting one another after two operations started from the same snapshot.

Secret and opaque bytes cross UniFFI as `Vec<u8>` because generated bindings cannot carry Rust
zeroization types. Rust adapters wrap inbound secret-bearing bytes immediately before validation or
early return, and returned secret-bearing values are limited to the API surfaces that already
define caller ownership of those bytes. Canonical public key bytes cross unchanged and are validated
at adapter boundaries before Core operations use them.

## Scope Boundary

This record fixes the binding ownership and atomicity contract. Existing protocol ADRs remain the
source of truth for sealed-sender framing, deduplication, contacts, blocking, event streams, backup,
and prekey lifecycle behavior.

## Considered Options

- Store protocol state inside a long-lived UniFFI object. Rejected because it would create a second
  authoritative state owner and weaken host-controlled crash consistency.
- Expose decoded protocol-state records to Swift and Kotlin. Rejected because decoded ratchet and
  replay state would couple clients to internal wire shapes and increase the secret-bearing API
  surface.
- Check generated Kotlin and Swift into the repo. Rejected because current CI already verifies
  generation from source, and checked-in generated output would add review noise without improving
  the binding contract.

## Verification Evidence

- `crates/aether-uniffi/docs/api-coverage.md` maps issue 122 surfaces to generated Swift/Kotlin
  fixture replay and records opaque state, atomic mutation outputs, commit checks, and FFI error
  mappings.
- `scripts/test/binding-fixture-replay.sh` exercises generated bindings through the fixture replay
  harness.
- `crates/aether-core/tests/fixtures/protocol_state_blobs_v1.md` records that consumers persist
  Protocol State Blobs opaquely by kind/key without inspecting contents.
