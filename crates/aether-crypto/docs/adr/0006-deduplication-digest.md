# Deduplication via Keyed-BLAKE3 Digest

**Status:** Accepted

Received messages are deduplicated before decryption by a 16-byte keyed-BLAKE3 digest of the encrypted bytes, with the key derived per-identity so digests cannot be correlated across identities or precomputed by an outside party. The digest set is bounded with a consumer-supplied capacity, evicts oldest-first as a sliding window, and is persisted as protocol state so deduplication survives restart. Deduplicating ahead of decryption drops benign duplicates cleanly before the Double Ratchet would otherwise consume a one-time message key — it is one of three layered replay defenses, alongside the ratchet's own counter-based rejection and the idempotent acknowledgment-and-retry handling for any replay surviving the first two layers.
