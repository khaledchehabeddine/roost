# Received Message Deduplication

Core spots a repeated delivery, including an X3DH first message, by its Deduplication Digest before decrypting it, because the MessageID is still encrypted and a duplicate must never reach the ratchet, and it records a digest only after its Message decrypts and is accepted, so a Message that fails to decrypt leaves no digest behind. A duplicate is a normal receive result, not an error, and the Double Ratchet's replay check catches anything the digest misses. A Message resent by recovery has new bytes but its original MessageID, so the app, which stores every MessageID anyway, shows one Message per sender and MessageID while still committing and acknowledging each copy.

## Alternatives

- Let the transport deduplicate: each delivery route would apply its own replay policy.
- Keep every digest: senders could grow stored state without limit.
- Let Core remember recent MessageIDs per contact: it would need a limit, and no limit covers every resend while the Relay holds a Message.
