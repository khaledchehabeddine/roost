# Restoring a Backup as a Snapshot

A backup is a snapshot, and the sessions in it went on using message keys after it was taken. So a restore keeps the contact records the app backs up with its own database, and drops every session, pending acknowledgment, and the deduplication set. Each contact comes back without a new link, and the restored side's next message to an accepted contact starts a new session.

## Alternatives

- Restore sessions too: the restored device would encrypt new messages with message keys its old copy already used.
- Drop the contacts too: every contact would need a new link, and every open request would be lost.
