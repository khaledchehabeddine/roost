# Signing Established Messages

The sender signs the message transcript of each established message with their identity key, naming the recipient and the session ID. So nobody can pass off a session as belonging to an identity that didn't take part, and by design a sender can't deny writing a message after the handshake. The signature travels sealed, so the relay can't see it.

## Alternatives

- Sign with the discovery key: it would use the permanent key less, but authorship must trace back to the identity key.
