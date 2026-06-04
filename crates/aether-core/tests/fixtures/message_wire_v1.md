# Message Wire v1 Fixtures

These fixtures pin the v1 Postcard Message encoding. Consumers can decode each `encoded_hex` value, compare every decoded field with the JSON expectations, re-encode the Message, and compare the bytes to the original hex to detect unintended encoding changes before release.

The Message version byte is controlled by the library and lives inside the encoded Message bytes. It is separate from any transport envelope, header, content type, or routing metadata that a consumer may place around the opaque Message payload.

The `text` payload kind identifies encrypted application text bytes in the Message envelope. Fixture payload bytes are synthetic opaque bytes and must not be treated as plaintext examples.
