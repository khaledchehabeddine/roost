# Message Wire v1 Fixtures

These fixtures pin the current pre-release Postcard Message encoding. Consumers can decode each `encoded_hex` value, compare every decoded frame field with the JSON expectations, re-encode the Message, and compare the bytes to the original hex to detect unintended encoding changes before release.

The Message bytes are the canonical sealed-sender frame: version, recipient Discovery Key public key, optional X3DH pre-key reference, per-message ephemeral public key, and ciphertext.

These fixtures lock the absence of sender fields and decrypted metadata from the Message wire shape. Message ID, timestamp, payload kind, ratchet header, sender IK material, sender certificate, and sender signature are encrypted inside the frame or covered by protocol-state tests.

Old pre-release sender-visible Message layouts are non-canonical. They are supported only as explicit rejection inputs in tests, not as current fixtures.
