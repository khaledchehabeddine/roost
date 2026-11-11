# Signing Established Messages

The sender signs each established message with their identity key, over a transcript that names the recipient and the session ID. So nobody can pass off a session as belonging to an identity that didn't take part. By design, a sender also can't deny writing a message after the handshake.

## Alternatives

- Sign with the discovery key: it would use the permanent key less, but authorship must trace back to the identity key.
