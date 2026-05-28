# Encrypted Identity Backup Design

**Status:** Accepted

Identity backups are a self-describing encrypted file: XChaCha20-Poly1305 over a key derived from the passphrase via Argon2id, with the version byte and the Argon2id parameters carried in the file itself, the version included in the AEAD's associated data so it cannot be altered without failing authentication, and the passphrase normalized to canonical Unicode form before derivation. The library refuses to produce or read a backup whose Argon2id memory cost falls below a normative floor, so neither an old file nor a hostile one can downgrade the work factor. Secret material is zeroized once unneeded, and the library publishes backup-format test vectors so a backup written under one library version stays readable under another.
