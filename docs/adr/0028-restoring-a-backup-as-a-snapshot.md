# Restoring a Backup as a Snapshot

An identity backup holds only the identity key and the current discovery key. The app backs up contact records with its own database. A backup may be old or copied, so a restore drops every session, pending acknowledgment, and the deduplication set, and leaves prekeys unusable until the next inbox rotation.

## Alternatives

- Restore sessions too: the restored device would reuse message keys its old copy already used.
- Create prekeys right after a restore: they could reuse prekey IDs the backed-up identity already published.
- Drop the contacts too: every contact would need a new link.
