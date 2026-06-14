# Protocol State Invariant Tests

Issue 114 coverage uses bounded generated traces plus deterministic negative scenarios. These tests
verify the public contract without treating ADR or context documents as executable code.

## Generated Trace Model

Generated traces produce short sequences of encrypted Messages over one Session. The model records
the expected plaintext for each Message, delivers Messages in generated order, and asserts each
accepted Message decrypts exactly once. Replays run after the receiver commits advanced blobs, so
byte-identical retries must hit the Deduplication Set before Ratchet state is loaded or mutated.

The crypto-only trace model exercises the Ratchet directly. It covers bidirectional sends,
out-of-order delivery inside skipped-key bounds, replay rejection after state advancement, and
continued use after the final generated step.

## Serialized Host-Store Model

Core tests model a host store that owns Protocol State Blobs. Each operation reads a snapshot,
returns updates, and commits through a transaction token. The model rejects stale commits and
conflicting writes, proving Library Instances do not reuse forked authoritative in-memory state
across operations.

## Rollback And Corruption Model

Rollback tests commit only complete update sets. If a simulated host commit is interrupted, the
last fully committed Message, advanced Protocol State Blob, and Deduplication Set remain the only
visible state. Corruption tests replace committed blobs with malformed bytes and assert Core
surfaces decode faults rather than silently reinitializing state.

## Session Recovery Model

Dead Session tests use the existing unrecoverable-session marker. The first observation emits one
Session-Unrecoverable Event with a state update that records the event as emitted. Later Messages
under the same Dead Session return the same unrecoverable outcome without duplicate events or
automatic X3DH churn. Installing a replacement Session is the caller-visible recovery path.
