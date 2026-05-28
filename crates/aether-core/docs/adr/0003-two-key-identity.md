# Two-Key Identity Model

**Status:** Accepted

Identity comprises two keypairs: a permanent identity key (IK) that is the cryptographic identity, and a rotatable discovery key (DK) signed by the IK. Each keypair pairs an Ed25519 signing key with X25519 material; both are persisted to platform-provided secure storage, and DK rotation produces a fresh DK plus a fresh prekey bundle while the IK never rotates. Splitting identity from discovery means safety numbers and sender-certificate validity bind to the IK and survive rotation, while DK rotation drives prekey-bundle freshness without disturbing trust.
