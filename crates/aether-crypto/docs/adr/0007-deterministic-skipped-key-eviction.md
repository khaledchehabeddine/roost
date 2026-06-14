# Deterministic Skipped-Key Cap Rejection

**Status:** Accepted

The Double Ratchet skipped-key cache rejects messages that would exceed the global skipped-key cap.
Rejection preserves all retained skipped keys, avoids attacker-induced loss of decryptable
out-of-order messages, and lets Core reject the Message without mutating live Session state.
Incoming ratchet headers are not authenticated until AEAD verification succeeds, so skipped-key cap
overflow is not by itself a Dead Session signal.

## Consequences

- Persisted ratchet state still rejects oversized skipped-key caches during deserialization.
- Callers must treat skipped-key cap overflow as a rejected Message under the same ratchet state,
  not as proof that the Session is unrecoverable.
