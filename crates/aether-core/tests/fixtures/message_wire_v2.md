# Message Wire v2 Fixtures

These fixtures pin the v2 Postcard Message encoding. Consumers can decode each `encoded_hex` value, compare every decoded transport-visible field with the JSON expectations, re-encode the Message, and compare the bytes to the original hex to detect unintended encoding changes before release.

The Message version byte is controlled by the library and lives inside the encoded Message bytes. It is separate from any transport envelope, header, content type, or routing metadata that a consumer may place around the opaque Message payload.

These fixtures lock the absence of sender fields from the Message wire shape. Sender identity key, sender certificate, and sender signature are not Message fields, fixture metadata required for decoding, or associated data; sealed-sender payload semantics are covered by protocol-state tests.

Old pre-release sender-visible Message layouts are non-canonical. They are supported only as explicit rejection inputs in tests, not as current fixtures.
