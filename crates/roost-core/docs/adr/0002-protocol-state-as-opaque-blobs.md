# Protocol State as Opaque Blobs

**Status:** Accepted

Ratchet/session state, deduplication sets, pending acknowledgments, and contact state are produced
by the library as opaque Protocol State Blobs and persisted by the consumer through a get/set
interface, because the consumer owns persistence on the platform and inspecting blob contents on
either side would couple the two layers tightly. PreKey State is KeyStore-owned secure-storage
state, and Sender Certificates are caller validation inputs rather than current decoded Protocol
State Blob bodies; workspace ADR 0005 and [Core ADR 0012](0012-prekey-lifecycle-and-session-recovery.md)
own that refined release boundary. The library holds no authoritative in-memory copy across
operations, so each blob is loaded at operation start and the advanced blob is written back at the
end through a consumer-serialized transaction.

The consumer's store must protect Protocol State Blobs at rest with confidentiality and integrity
controls comparable to identity-key storage, must commit atomically and durably with any outbox or
acknowledgment side effect, and must treat blob decode failures as faults rather than silently
reinitializing state. Silent reinitialization can roll Ratchet state backward, drop deduplication or
pending-acknowledgment history, and break forward secrecy or idempotency.

## Verification Evidence

- `docs/adr/0005-protocol-state-interface-and-concurrent-instances.md` records the current
  cross-crate protocol-state contract and host serialization requirement.
- `crates/roost-core/tests/fixtures/protocol_state_blobs_v1.md` records the current decoded blob
  bodies and opaque consumer-storage expectations.
