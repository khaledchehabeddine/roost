# Encrypted Identity Backup

An Identity Backup holds the Identity Key and the current Discovery Key, so a restore on a new Device continues the same Identity, and peers don't see a fresh one. Argon2id derives the encryption key from the passphrase because it resists offline guessing, and the backup authenticates its Argon2id settings so an attacker can't weaken them. A restore leaves prekeys unusable until the next inbox rotation advances the Epoch, so an old or copied backup can't reuse published prekey IDs.

## Alternatives

- Accept weak Argon2id settings for compatibility: anyone holding the file could guess the passphrase offline.
- Restore Sessions too: Sessions are live state that the app stores, with their own recovery.
