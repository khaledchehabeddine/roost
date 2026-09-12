# Deduplication Approach

**Status:** Accepted

Received encrypted Messages are deduplicated before decryption by computing BLAKE3 in keyed mode over the encrypted Message bytes available to Core before Ratchet decryption, then storing the first 16 bytes of the keyed hash output. The BLAKE3 key is a dedicated 32-byte CSPRNG secret generated once per local Identity, used only for deduplication, and persisted inside the deduplication-set Protocol State Blob; Identity, Discovery Key, and Ratchet secrets are never reused as digest keys. This gives each Identity a separate digest namespace while keeping digest output stable across process restart. There is no derivation from existing secrets; domain separation comes from the single-purpose per-Identity key. Any future KDF replacement must use a distinct, non-empty info string and preserve the same per-Identity scope.

The receive path checks the digest set before decryption and before any Ratchet/session-state mutation. A digest hit drops the duplicate at this layer, produces no new acknowledgment, and may only re-expose an already-pending acknowledgment for the same Message; no duplicate user-visible effect is allowed. A digest miss proceeds to normal decryption without recording the digest yet. After successful decryption and acceptance, Core records the digest in the bounded sliding window as part of the same advanced protocol-state update; failed decrypts and Ratchet replay rejections do not advance deduplication state.

The deduplication set capacity is consumer-supplied, defaults to 1024 digests, has a minimum of 64 digests, has a hard maximum of 2048 digests, and rejects capacities outside that range. When recording an accepted miss would exceed capacity, eviction is oldest-first. The set is persisted as protocol state using the current Protocol State Blob `1.0` envelope behavior, including unsupported major-version rejection before payload decode; corrupt blobs are faults rather than reset signals.

## Replay Layers

- Pre-decryption digest deduplication rejects byte-identical encrypted Message retries before Ratchet state is touched.
- Double Ratchet replay rejection rejects cryptographic replays and out-of-window counters after decryption starts.
- Idempotent acknowledgment/retry handling absorbs delivery retries that survive the first two layers without producing duplicate user-visible effects.

## Considered Options

- Encrypted-payload message IDs. Rejected. IDs inside the encrypted payload are unavailable before decryption, so they cannot protect the Ratchet from duplicate ciphertext retries.
- Post-decryption-only rejection. Rejected. A duplicate could touch Ratchet/session state before being identified, which is the failure this layer exists to prevent.
- Transport-owned deduplication. Rejected. Transports do not own protocol state, may differ across delivery paths, and cannot enforce one replay policy across all consumers.
- Unbounded digest set. Rejected. Replay defense must not let external input grow persisted state without a hard cap.
