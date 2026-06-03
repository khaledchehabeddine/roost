# Deterministic Skipped-Key Eviction

**Status:** Accepted

The Double Ratchet skipped-key cache evicts the oldest first-observed skipped key when its global capacity is reached. Eviction age is tracked independently of the skipped key's public-key ordering, so attacker-chosen public keys do not control which cached key is dropped.

## Consequences

- Persisted ratchet state must preserve enough ordering metadata for eviction to remain stable after reload.
- A large authentic out-of-order flood can evict the oldest cached key, but it cannot choose victims by public-key sort order.
