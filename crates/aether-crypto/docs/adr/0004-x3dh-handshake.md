# X3DH Handshake

**Status:** Accepted

Initial session establishment uses a sender-anonymous X3DH-derived handshake against the recipient's current discovery-key epoch, combining Diffie-Hellman over the initiator ephemeral key, responder discovery key, responder signed pre-key, and a responder one-time pre-key when available. The initiator discovery key is sealed inside the first message and contributes to a private sender key-possession proof, not to transport-visible fields or the ratchet root-key transcript. X3DH is chosen because one-time pre-keys improve first-message forward secrecy while preserving asynchronous session setup, and the cloud relay can store and serve the one-time-prekey pool that X3DH-Lite avoided. The permanent identity key signs the discovery key but does not participate in routine X3DH key agreement.
