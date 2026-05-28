# Encrypted Identity Backup Design

**Status:** Accepted

Identity backups are a fixed 120-byte self-contained blob — `[salt (16B)] + [nonce (24B)] + [ciphertext (80B)]` — encrypted with XChaCha20-Poly1305 using a 32-byte key stretched from the passphrase via Argon2id (m=65536 KiB, t=3, p=1), with salt and nonce re-randomized on every export. Argon2id's memory-hard design defeats GPU/ASIC brute-force; the 192-bit extended nonce tolerates random generation without collision concern; Poly1305 makes wrong passphrase or corruption deterministically detectable; the fixed-length blob validates on import with a single length check.
