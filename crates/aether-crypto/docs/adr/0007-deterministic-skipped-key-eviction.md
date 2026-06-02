# Deterministic Skipped-Key Eviction

**Status:** Accepted

The Double Ratchet skipped-key cache keeps the per-chain `MAX_SKIP = 100` guard and bounds total cached keys at 500, evicting the oldest first-inserted key when the total cap is exceeded. Age is stored as a monotonic sequence in the ratchet wire state, so eviction is deterministic across rollback and reload without letting attacker-chosen public keys control which cached key is dropped.

## Consequences

- Ratchet state wire format is version 2; version 1 is not migrated pre-release.
- A large authentic out-of-order flood can evict the oldest cached key, but it cannot choose victims by public-key sort order.
