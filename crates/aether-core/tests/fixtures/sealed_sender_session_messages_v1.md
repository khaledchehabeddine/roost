# Sealed-Sender Session Message v1 Fixtures

These fixtures pin a sealed-sender session Message together with the recipient state fixture needed to decrypt it. The sender state and recipient state names refer to `protocol_state_blobs_v1.json`.

Fixture bytes are deterministic test-only material generated from the same setup as the Protocol State Blob fixtures. They have no production origin.

Transport-visible expectations contain only Message fields available before decrypt: ID, recipient public key, timestamp, payload kind, and opaque payload bytes. Sender identity key, sender certificate, and sender signature appear only under `post_decryption`.

Binding replay should:

- decode and re-encode `encoded_hex` byte-for-byte
- verify transport-visible fields match `transport_visible`
- decrypt with the referenced recipient state fixture and `sender_certificate_validation`
- verify plaintext and `post_decryption` sender material only after successful decrypt
- reject tampered ciphertext without returning sender identity material

Old pre-release sender-visible message layouts are not part of this canonical set.
