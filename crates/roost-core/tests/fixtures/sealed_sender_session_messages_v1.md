# Sealed-Sender Session Message v1 Fixtures

These fixtures pin a sealed-sender session Message together with the recipient state fixture needed to decrypt it. The sender state and recipient state names refer to `protocol_state_blobs_v1.json`.

Fixture bytes are deterministic test-only material generated from the same setup as the Protocol State Blob fixtures. They have no production origin.

Transport-visible expectations contain only frame fields available before decrypt: version, recipient Discovery Key public key, optional pre-key reference, per-message ephemeral public key, and ciphertext. Message ID, timestamp, payload kind, sender IK X25519 bytes, sender IK Ed25519 bytes, the IK binding signature, sender certificate, and sender signature appear only after decrypt.

`sender_certificate_validation.relay_domain` is the domain a replaying harness must pass as the expected relay domain. It is pinned here rather than hardcoded in each harness so the Rust replay validate against the same value the certificate was signed over — a certificate naming a different domain must be rejected, so a harness supplying its own constant could pass while disagreeing with the fixture.

The Rust replay checks:

- decode and re-encode `encoded_hex` byte-for-byte
- verify transport-visible frame fields match `transport_visible`
- decrypt with the referenced recipient state fixture and `sender_certificate_validation`
- verify plaintext and `post_decryption` sender material only after successful decrypt
- reject tampered ciphertext without returning sender identity material

Old pre-release sender-visible message layouts are not part of this canonical set.
