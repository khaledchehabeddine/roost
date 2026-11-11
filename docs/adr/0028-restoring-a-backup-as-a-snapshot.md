# Restoring a Backup as a Snapshot

An identity backup holds only the identity key and the current discovery key, so peers see the restored identity as the same one, and the app backs up the contact records with its own database. The backup is a snapshot that may be old or copied, so a restore drops every session, pending acknowledgment, and the deduplication set, and leaves the prekeys unusable until the next inbox rotation.

## Alternatives

- Restore sessions too: the restored device would encrypt new messages with message keys its old copy already used.
- Create prekeys right after a restore: they could reuse prekey IDs that the backed-up identity already published.
- Drop the contacts too: every contact would need a new link, and every open request would be lost.
