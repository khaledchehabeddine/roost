# Identity Binding and Message Authenticity

A Message that carries the X3DH handshake proves its sender holds their Identity Key, and every later Message's transcript is signed with the sender's Identity Key and names the recipient and SessionID, so nobody can pass off a Session as belonging to an Identity that didn't take part. X3DH leaves the Identity Keys out of the root key, because their public bytes prove nothing, and needing them before decryption would expose the sender to anyone holding the recipient's Discovery Key. Signatures travel sealed so the transport can't see them, and by design a sender can't later deny writing any Message after the handshake.

## Alternatives

- Mix both Identity Keys into the root key: the responder would need the sender's Identity Key before decrypting, so it would sit where a leaked Discovery Key reveals it.
- Sign Messages with the Discovery Key: this would use the permanent key less, but authorship must trace back to the Identity Key.
