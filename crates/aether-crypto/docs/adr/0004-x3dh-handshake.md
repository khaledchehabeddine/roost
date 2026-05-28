# X3DH Handshake

**Status:** Accepted

Initial session establishment uses an X3DH handshake against the recipient's prekey bundle (signed pre-key plus one-time pre-keys), performing Diffie-Hellman over four inputs — identity key, ephemeral key, signed pre-key, and a one-time pre-key when one is available — combined via HKDF-SHA256 with a protocol-specific info string. A one-time pre-key is consumed per handshake; the signed pre-key (rotated weekly) is the fallback when OPKs are exhausted, and the bundle belongs to the responder's current discovery key epoch so DK rotation invalidates the prior epoch's pre-keys. Builds on the Curve25519 primitives in [DR 0001](0001-cryptographic-primitive-selection.md).
