# Identity Binding and Message Authenticity

A Message that carries the X3DH handshake proves its sender holds their Identity Key, and the sender signs every later Message's transcript with that key, naming the recipient and SessionID. So nobody can pass off a Session as belonging to an Identity that didn't take part, and by design a sender can't deny writing a Message after the handshake. Signatures travel sealed so the transport can't see them, and X3DH leaves the Identity Keys out of the root key, because their public bytes prove nothing.

## Alternatives

- Mix both Identity Keys into the root key: the responder would need the sender's Identity Key before decrypting, so it would sit where a leaked Discovery Key reveals it.
- Sign Messages with the Discovery Key: this would use the permanent key less, but authorship must trace back to the Identity Key.
