# Message Key and Nonce Derivation

**Status:** Accepted

Each ratchet message key is expanded via HKDF-SHA256 with a protocol-specific info string and no salt into a 32-byte XChaCha20-Poly1305 encryption key and 24-byte Nonce; the Nonce is not transmitted and the receiver re-derives it from its symmetrically derived message key. A distinct info string domain-separates this derivation from other HKDF outputs in the crate to prevent cross-protocol key reuse, and salt is omitted per RFC 5869 §3.1 since the chain-derived input is already pseudo-random.
