# Two-Key Identity

**Status:** Accepted

Identity is split into a permanent identity key (IK) and a rotatable discovery key (DK) because conflating identity with discovery would force a choice between constant identity rotation, which breaks trust continuity, and permanent prekey-bundle exposure, which limits forward secrecy. The IK carries the cryptographic identity that safety numbers and sender certificates bind to, while the IK-signed DK drives prekey-bundle freshness and serves as the X3DH identity key for the current discovery epoch. DK rotation produces a fresh DK and fresh prekey bundle without touching the IK, so a peer rotating their DK does not invalidate existing trust or in-flight safety numbers.
