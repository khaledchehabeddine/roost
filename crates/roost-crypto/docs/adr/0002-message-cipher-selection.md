# Message cipher selection

**Status:** Accepted

Use XChaCha20-Poly1305 for authenticated encryption. It avoids requiring AES hardware acceleration
across the mobile device range. The extended nonce also accommodates random nonces in passphrase
backup envelopes; ratchet messages instead derive each nonce with its single-use key as described
in [ADR 0003](0003-message-key-and-nonce-derivation.md).
