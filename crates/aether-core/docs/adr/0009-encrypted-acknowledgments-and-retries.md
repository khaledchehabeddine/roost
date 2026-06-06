# Encrypted Acknowledgments And Retry Instructions

**Status:** Accepted

Acknowledgments are encrypted Session Messages returned to the consumer for transport, and retry
behavior is exposed as instructions over persisted pending-acknowledgment Protocol State Blobs.
This keeps sender/receiver control metadata opaque to intermediaries while preserving the existing
consumer-owned transport and protocol-state commit boundary: Core records pending acknowledgments,
clears them when matching acknowledgments arrive, and never performs network IO.

## Considered Options

- Plain transport receipts. Rejected because intermediaries could observe delivery state and bind
  it to clear Message IDs outside the ratcheted channel.
- Core-managed retry transport. Rejected because consumers own networking, scheduling, and durable
  outbox commits.
- In-memory pending state. Rejected because multiple library instances and restarts must observe
  the same authoritative Protocol State Blob.
