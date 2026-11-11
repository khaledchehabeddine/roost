# Identity Keys in the Handshake

Unlike standard X3DH, Roost leaves both identity keys out of the root key, so the recipient doesn't need the sender's identity key to decrypt. The sender's identity key then travels only in the first message's innermost layer, where a leaked discovery key doesn't reveal it. The sender proof and the sender's signatures prove who wrote a message instead.
