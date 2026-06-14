# Signed Pre-Key v1 Fixtures

These fixtures pin the signed bytes and Ed25519 signature for public signed pre-key bundles.

Fixture bytes are deterministic test-only material from fixed signing-key and signed-prekey secret
seeds. They have no production origin.

The signed bytes are `AetherSPK-v1:` followed by the X25519 public key, big-endian epoch, and
big-endian creation timestamp. Replaying the fixture verifies the checked-in signature through the
public signed pre-key bundle API.
