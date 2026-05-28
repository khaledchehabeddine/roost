# Message Cipher Selection

**Status:** Accepted

XChaCha20-Poly1305 (via the `chacha20poly1305` crate's `XChaCha20Poly1305` type, 24-byte nonce) is the AEAD cipher for every ratcheted Message. Chosen over AES-256-GCM because budget Android SoCs lack guaranteed ARMv8 AES instructions and software AES is cache-timing-sensitive on cores without hardware support, so ChaCha-family ciphers — which run constant-time in software regardless of hardware — are the only choice that is uniformly safe across the target device matrix. Chosen over ChaCha20-Poly1305 specifically because the 24-byte extended nonce tolerates HKDF-derived or random nonces without the 12-byte variant's 2³² birthday bound; this composes cleanly with the message-key derivation in [DR 0003](0003-message-key-and-nonce-derivation.md), and the implementation shares audit surface with the Curve25519 primitives in [DR 0001](0001-cryptographic-primitive-selection.md).
