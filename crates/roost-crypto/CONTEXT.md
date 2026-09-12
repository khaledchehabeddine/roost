# Crypto

Keys, derivation, X3DH, and Double Ratchet mechanics. Core owns their persistence and lifecycle.

## Language

**Message Nonce**:
The 24-byte XChaCha20 nonce derived alongside each ratchet message's single-use encryption key.
The receiver derives the same nonce; it is not transmitted.
_Avoid_: random message nonce, salt

**Sealed Frame Agreement**:
Per-frame X25519 agreement between a fresh ephemeral key and the recipient's Discovery Key,
expanded into the outer AEAD key and nonce. Frame fields and length-framed external associated
data authenticate without exposing sender material.
_Avoid_: X3DH root key, ratchet message key

**Ratchet**:
The Double Ratchet state machine for one Session. Per-step and total skipped-key caps reject
excessive inputs without evicting retained keys needed for out-of-order messages.
_Avoid_: chain, transport state

**X3DH**:
The identity-bound handshake over the initiator ephemeral key and responder discovery, signed
prekey, and optional one-time prekey. It seeds the Ratchet and seals sender material in the first
message; certificate trust remains a Core verdict.
_Avoid_: login, certificate validation

**Identity Misbinding**:
Relabeling agreement output or Message authorship under a different Identity Key from the verified
peer. Identity key-half bindings, IK-bound X3DH, and sealed IK Message signatures prevent this.
_Avoid_: identity mismatch, wrong peer
