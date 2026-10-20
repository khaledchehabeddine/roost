# Showing Resent Messages Once

A Message that recovery resends has new bytes, and so a new Deduplication Digest, but keeps its MessageID. The app already stores every MessageID, so it shows one Message per sender and MessageID, while still committing and acknowledging each copy.

## Alternatives

- Let Core remember recent MessageIDs per contact: it would need a limit, and no limit covers every resend while the Relay holds a Message.
