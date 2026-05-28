# Cryptographic Primitive Selection

**Status:** Accepted

X25519 (key exchange) and Ed25519 (signing) are the cryptographic primitives for Aether, both derived from Curve25519 via the audited `x25519-dalek` and `ed25519-dalek` crates (built on `curve25519-dalek`). Curve25519 is chosen for constant-time arithmetic by design, compact 32-byte keys, transparent parameter design free of unexplained NIST constants, and shared audit surface across key exchange and signing — one curve, one audit, proven in Signal and Tor production deployments.
