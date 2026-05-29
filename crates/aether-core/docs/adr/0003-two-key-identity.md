# Two-Key Identity

**Status:** Accepted

Identity is split into two keypairs because conflating identity with discovery would force a choice between constant identity rotation (breaking trust continuity) and permanent prekey-bundle exposure (limiting forward secrecy): a permanent identity key (IK) carries the cryptographic identity that safety numbers and sender certificates bind to, and a rotatable discovery key (DK) — signed by the IK — drives prekey-bundle freshness for new session establishment. Each keypair pairs an Ed25519 signing key with X25519 key-agreement material so signing and key-agreement run independently under their dedicated primitives, and both keypairs are persisted to platform-provided secure storage so the host OS guards them at rest. DK rotation produces a fresh DK and a fresh prekey bundle without touching the IK, so a peer rotating their DK does not invalidate existing trust or in-flight safety numbers.
