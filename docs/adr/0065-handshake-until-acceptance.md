# Handshake Until Acceptance

A Requester holds no Delivery Capability for the peer's inbox until the peer accepts, and without one the Relay admits a Message only against the peer's current prekeys. So every Message on a Contact Request's Session carries the handshake until the peer accepts, not just until its first reply.

## Alternatives

- End a request's handshake at the first reply: the Requester couldn't reach the peer's inbox until the peer accepted.
