# Sender-Proof Transcript

A first message proves the sender holds their identity key with a Diffie-Hellman proof that only the recipient can check. The proof covers the handshake's public keys, prekey choice, and sender certificate, so fields copied from one handshake can't be reused in another. The cost is that whoever holds a recipient's signed prekey can forge first messages to that recipient until the prekey rotates.

## Alternatives

- Sign the first message: the recipient could prove to anyone who contacted them.
- Prove with the discovery key: a stranger can't tell an old discovery key from the current one, so one leaked old key would let anyone send first messages as the sender.
