# Message Key and Nonce Derivation

**Status:** Accepted

Each ratchet message key is expanded by a single HKDF-SHA256 call (protocol-specific info string, no salt) into both the 32-byte XChaCha20-Poly1305 encryption key and the 24-byte Nonce; the Nonce is omitted from the wire so the receiver re-derives it from its own symmetrically derived message key. Deriving the Nonce alongside the key saves the 24 bytes of wire overhead per message without weakening security because each message key is used exactly once — there is no reuse risk a random nonce would protect against. The info string is distinct from every other HKDF call in the crate so cross-protocol key reuse is impossible by construction, and salt is omitted per RFC 5869 §3.1 because the chain-derived input is already pseudo-random.
