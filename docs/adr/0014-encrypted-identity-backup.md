# Encrypted Identity Backup

An Identity Backup holds the Identity Key and the current Discovery Key, so a restore on a new Device continues the same Identity, and peers don't see a fresh one. Argon2id derives the encryption key from the passphrase because it resists offline guessing, and the backup authenticates its Argon2id settings so an attacker can't weaken them.

## Alternatives

- Accept weak Argon2id settings for compatibility: anyone holding the file could guess the passphrase offline.
- Put contacts and Sessions in the backup too: the app already backs up its database, which holds them (ADR 0074).
