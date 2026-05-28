# Message Cipher Selection

**Status:** Accepted

XChaCha20-Poly1305 (via the `chacha20poly1305` crate's `XChaCha20Poly1305` type, 24-byte nonce) is the AEAD cipher for every ratcheted Message in Aether. Chosen over AES-256-GCM because budget Android SoCs lack guaranteed ARMv8 AES instructions and software AES is cache-timing-sensitive on cores without hardware support; chosen over ChaCha20-Poly1305 because the 24-byte extended nonce tolerates HKDF-derived or random nonces without the 12-byte variant's 2³² birthday bound. Shares audit surface with the Curve25519 primitives in [DR 0001](0001-cryptographic-primitive-selection.md).
