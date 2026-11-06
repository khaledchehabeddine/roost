# Showing Resent Messages Once

A message that recovery resends has new bytes, and so a new deduplication digest, but keeps its message ID. The app already stores every message ID, so it shows one message per sender and message ID, while still committing and acknowledging each copy.

## Alternatives

- Let Core remember recent message IDs per contact: it would need a limit, and no limit covers every resend while the relay holds a message.
