# X3DH Handshake

**Status:** Accepted

Initial session establishment uses an identity-bound X3DH-derived handshake against the recipient's current discovery-key epoch, combining Diffie-Hellman over the initiator ephemeral key, responder discovery key, responder signed pre-key, and a responder one-time pre-key when available. The root-key transcript additionally binds both parties' canonical Identity Key encodings, after each IK X25519 half is verified under its IK Ed25519 binding signature, so the resulting session cannot be re-labeled under another identity. Sender material remains sealed inside the first message and is not transport-visible; the accepted trade-off is that first-contact decrypt now requires caller-provided candidate sender IK material. See workspace ADR 0008 for the identity-misbinding boundary.
