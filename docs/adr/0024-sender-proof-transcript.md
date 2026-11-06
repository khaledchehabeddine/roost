# Sender-Proof Transcript

The first message that creates a session proves the sender holds their identity key with a Diffie-Hellman proof only the recipient can check, not a signature anyone could verify. The proof covers the handshake's public keys, the prekey choice, and the sender's identity key, discovery key, and certificate, so fields copied from one handshake can't be pasted into another. Forging a first message takes the sender's identity key, and the cost is that whoever holds a recipient's signed prekey can forge first messages to that recipient until the prekey rotates.

## Alternatives

- Sign the transcript with Ed25519: the recipient could prove to anyone who contacted them.
- Prove with the sender's discovery key: a stranger can't tell an old discovery key from a current one, so one leaked old key would let anyone send first messages as the sender.
- Prove only the shared secret: the handshake fields could then be swapped.
