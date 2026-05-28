# Protocol State as Opaque Consumer-Persisted Blobs

**Status:** Accepted

Cryptographic and protocol state — ratchet/session, prekeys, sender certificate, deduplication set, pending acknowledgments — is produced by the library as opaque byte blobs and persisted by the consumer through a get/set interface that the consumer never inspects. The library loads each blob at the start of an operation and writes the advanced blob back at the end, holding no authoritative in-memory copy across operations, so concurrent instances can run against the same identity as long as the consumer serializes mutations through a single write transaction over its store. The consumer's store must be atomic + durable, crash-consistent, and integrity-preserving; a blob that fails to decode is a fault rather than a trigger to silently reinitialize, which would otherwise risk a ratchet rollback.
