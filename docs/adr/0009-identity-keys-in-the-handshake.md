# Identity Keys in the Handshake

X3DH starts a session from the recipient's discovery key and prekeys, and leaves both identity keys out of the root key. The sender's identity key travels only in the first message's innermost layer, so a leaked discovery key alone doesn't reveal who sent it. The sender proof and the sender's signatures prove who wrote a message instead (ADR 0002, ADR 0010).

## Alternatives

- Mix both identity keys into the root key, as standard X3DH does: the recipient would need the sender's identity key before decrypting, so it would sit where a leaked discovery key reveals it.
