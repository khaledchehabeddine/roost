# Two-Key Identity

**Status:** Accepted

Identity is split into a permanent identity key (IK) and a rotatable discovery key (DK) because conflating identity with discovery would force a choice between constant identity rotation, which breaks trust continuity, and permanent prekey-bundle exposure, which limits forward secrecy. The IK carries the cryptographic identity that safety numbers and sender certificates bind to, while the IK-signed DK drives prekey-bundle freshness and serves as the X3DH identity key for the current discovery epoch. DK rotation produces a fresh DK and fresh prekey bundle without touching the IK, so a peer rotating their DK does not invalidate existing trust or in-flight safety numbers.

## Consequences

- Loading the identity returns only the IK and does not check the DK. The DK's signature is verified when it is read for use, so a corrupt or absent DK never blocks loading the IK, and rotation repairs it because minting a fresh DK needs only the IK.
- The DK is included in the encrypted identity backup, so restoring onto a new device continues the same epoch lineage rather than starting fresh. Import validates the restored DK signature against the restored IK before any storage changes begin, then commits the DK as its own signed blob and re-verifies it on read. An interrupted import that lands the IK without the DK degrades to a detectable, re-mintable state instead of a silent hybrid. Peers judge DK freshness from its signed timestamp and the IK signature, not from epoch magnitude.
