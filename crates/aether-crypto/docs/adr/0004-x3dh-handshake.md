# X3DH Handshake

**Status:** Accepted

Initial session establishment uses Signal's full X3DH handshake against the recipient's current discovery-key epoch, combining Diffie-Hellman over the initiator discovery key, initiator ephemeral key, responder discovery key, responder signed pre-key, and a responder one-time pre-key when available. X3DH is chosen because one-time pre-keys improve first-message forward secrecy while preserving asynchronous session setup, and the cloud relay can store and serve the one-time-prekey pool that X3DH-Lite avoided. The permanent identity key signs the discovery key but does not participate in routine X3DH key agreement.
