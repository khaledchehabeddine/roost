# Crypto Protocol State

Double Ratchet and X3DH must reject invalid transitions deterministically:

- **Replays rejected**: skipped-key cache uses `remove` on hit (consuming the key), restoring the entry if decrypt fails. Consume prevents replay; the restore prevents an attacker from burning legitimate keys via replays with tampered ciphertext
- **Out-of-order receipt**: try the skipped-key cache before advancing the chain, otherwise out-of-order messages destroy the state needed to decrypt them
- **Forward secrecy**: old chain keys overwritten by KDF advance. Consumed skipped keys are removed from the cache, otherwise leaked device state decrypts past sessions
- **State changes only on successful decrypt**: a decrypt path mutates a clone and replaces `self` only after AEAD verification succeeds (which authenticates the header as AAD). Forged headers can't mutate live state
- **Hard caps, deterministic rejection**: `MAX_SKIP` rejects large per-chain gaps; `MAX_SKIPPED_KEYS_TOTAL` bounds the total skipped-key cache. Runtime overflow rejects the message before mutating live state, and deserialization rejects oversized persisted state
