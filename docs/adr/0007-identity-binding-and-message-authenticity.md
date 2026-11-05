# Identity Binding and Message Authenticity

A Message that carries the X3DH handshake proves its sender holds their Identity Key, and the sender signs the Message Transcript of each Established Message with that key, naming the recipient and SessionID. So nobody can pass off a Session as belonging to an Identity that didn't take part, and by design a sender can't deny writing a Message after the handshake. Signatures travel sealed so the transport can't see them.

## Alternatives

- Sign Messages with the Discovery Key: this would use the permanent key less, but authorship must trace back to the Identity Key.
