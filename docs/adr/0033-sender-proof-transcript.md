# Sender-Proof Transcript

The X3DH first message proves the sender holds their keys with a proof only the recipient can check, not a signature anyone could verify. The proof covers the handshake's public keys, the prekey choice, and the sender's Discovery Key and certificate, so fields copied from one handshake can't be pasted into another.

## Alternatives

- Sign the transcript with Ed25519: anyone could check it, so every first message would prove contact and lose X3DH's deniability.
- Prove only the shared secret: the handshake fields could then be swapped.
