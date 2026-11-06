# Leaving Identity Keys Out of the Root Key

X3DH leaves both identity keys out of the root key, because their public bytes prove nothing. The sender proof and the sender's signatures prove who wrote a message instead (ADR 0007, ADR 0024).

## Alternatives

- Mix both identity keys into the root key: the responder would need the sender's identity key before decrypting, so it would sit where a leaked discovery key reveals it.
