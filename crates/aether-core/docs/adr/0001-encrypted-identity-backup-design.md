# Encrypted Identity Backup Design

**Status:** Accepted

Identity backups are encrypted with XChaCha20-Poly1305 (the same AEAD chosen for messages) under a key derived from the user's passphrase via Argon2id, chosen for its memory-hard design that defeats GPU and ASIC brute-force at OWASP-baseline cost. The backup file is self-describing — version byte and Argon2id parameters carried inside, version included in the AEAD's associated data so it cannot be altered without failing authentication — and the library refuses to read or write any backup whose memory cost falls below a normative floor, blocking work-factor downgrade from old or hostile files. The passphrase is normalized to canonical Unicode form before derivation so the same characters typed on any platform produce the same key, secret material is zeroized once unneeded, and the library publishes backup-format test vectors so backups round-trip across library versions.

**Divergence (in flight):** the shipped backup is a fixed 120-byte layout — salt, nonce, identity-keypair ciphertext — with compile-time Argon2id parameters, no version byte, and no associated data; the self-describing format above is not yet implemented. Tracked in [#153](https://github.com/RelayNet/aether/issues/153).
