# Received Message Deduplication

Core spots a repeated delivery by its Deduplication Digest before decrypting it, because the MessageID is still encrypted and a duplicate must never reach the ratchet. Core records a digest only after its Message decrypts and is accepted, so a Message that fails to decrypt leaves no digest behind. A duplicate is a normal receive result, not an error, and the Double Ratchet's replay check catches anything the digest misses.

## Alternatives

- Let the transport deduplicate: each delivery route would apply its own replay policy.
- Keep every digest: senders could grow stored state without limit.
