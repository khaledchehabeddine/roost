# Identity Binding and Message Authenticity

X3DH mixes both Identity Keys into the Session's root key, after checking each one's self-signature, so nobody can pass off the Session as belonging to an Identity the peer didn't verify. The sender also signs every Message Transcript with its Identity Key, and the signature travels sealed so the transport can't see it. By design, a sender can't later deny writing a Message.

## Alternatives

- Leave Identity Keys out of the root key: first contact stays deniable, but the Session is tied only to prekeys.
- Sign Messages with the Discovery Key: this would use the permanent key less, but authorship must trace back to the Identity Key.
