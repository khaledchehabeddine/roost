# Sender-Proof Transcript

The X3DH first message proves the sender holds their Identity Key with a Diffie-Hellman proof only the recipient can check, not a signature anyone could verify. The proof covers the handshake's public keys, the prekey choice, and the sender's Identity Key, Discovery Key, and certificate, so fields copied from one handshake can't be pasted into another. Forging a first message takes the sender's Identity Key, and the cost is that whoever holds a recipient's signed prekey can forge first messages to that recipient until the prekey rotates.

## Alternatives

- Sign the transcript with Ed25519: the recipient could prove to anyone who contacted them.
- Prove with the sender's Discovery Key: a stranger can't tell an old Discovery Key from a current one, so one leaked old key would let anyone send first messages as the sender.
- Prove only the shared secret: the handshake fields could then be swapped.
