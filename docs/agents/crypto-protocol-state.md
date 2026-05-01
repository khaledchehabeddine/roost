# Crypto Protocol State

Double Ratchet and X3DH-lite must reject invalid transitions deterministically:

- **Replays rejected**: skipped-key cache uses `remove` on hit (consuming the key), restoring the entry if decrypt fails. Consume prevents replay; the restore prevents an attacker from burning legitimate keys via replays with tampered ciphertext
- **Out-of-order receipt**: try the skipped-key cache before advancing the chain, otherwise out-of-order messages destroy the state needed to decrypt them
- **Forward secrecy**: old chain keys overwritten by KDF advance. Consumed skipped keys are removed from the cache, otherwise leaked device state decrypts past sessions
- **State changes only on successful decrypt**: a decrypt path mutates a clone and replaces `self` only after AEAD verification succeeds (which authenticates the header as AAD). Forged headers can't mutate live state
- **Hard caps, reject on overflow**: `MAX_SKIP` and `MAX_SKIPPED_KEYS_TOTAL` bound the skipped-key cache, enforced at runtime and deserialization. On overflow, reject new traffic rather than evict, because the cache sorts by pubkey, not by time, so an attacker can choose pubkeys to drop a victim's cached keys
