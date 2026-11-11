# Identity Keys in the Handshake

X3DH leaves both identity keys out of the root key, so the sender's identity key can travel in the first message's innermost layer, where a leaked discovery key doesn't reveal it. The sender proof and the sender's signatures prove who wrote a message instead.

## Alternatives

- Mix both identity keys into the root key, as standard X3DH does: the recipient would need the sender's identity key before decrypting, so a leaked discovery key would reveal it.
