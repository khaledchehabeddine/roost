# Leaving Identity Keys Out of the Root Key

X3DH leaves both Identity Keys out of the root key, because their public bytes prove nothing. The Sender Proof and the sender's signatures prove who wrote a Message instead (ADR 0008, ADR 0031).

## Alternatives

- Mix both Identity Keys into the root key: the responder would need the sender's Identity Key before decrypting, so it would sit where a leaked Discovery Key reveals it.
