# Handshake Until Acceptance

A requester holds no delivery capability for the peer's inbox until the peer accepts, and without one the relay admits a message only against the peer's current prekeys. So every message on a contact request's session carries the handshake until the peer accepts, not just until its first reply.

## Alternatives

- End a request's handshake at the first reply: the requester couldn't reach the peer's inbox until the peer accepted.
