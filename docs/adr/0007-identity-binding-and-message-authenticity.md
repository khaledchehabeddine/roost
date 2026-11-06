# Identity Binding and Message Authenticity

The first message that creates a session proves its sender holds their identity key, and the sender signs the message transcript of each established message with that key, naming the recipient and session ID. So nobody can pass off a session as belonging to an identity that didn't take part, and by design a sender can't deny writing a message after the handshake. Signatures travel sealed so the transport can't see them.

## Alternatives

- Sign messages with the discovery key: this would use the permanent key less, but authorship must trace back to the identity key.
