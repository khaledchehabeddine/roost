# Received Message Deduplication

Core spots a repeated delivery, including a First Message, by a digest before the ratchet decrypts it, because the MessageID is still encrypted and a duplicate must never reach the ratchet. It records a digest only after its Message decrypts, so a Message that fails to decrypt leaves no digest behind. A duplicate the digest catches is a normal receive result, not an error, and the Double Ratchet's replay check rejects any it misses.

## Alternatives

- Let the transport deduplicate: each delivery route would apply its own replay policy.
- Keep every digest: senders could grow stored state without limit.
