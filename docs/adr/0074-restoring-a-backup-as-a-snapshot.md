# Restoring a Backup as a Snapshot

A backup is a snapshot, and the Sessions in it went on using message keys after it was taken. So a restore keeps the contact records the app backs up with its own database, and drops every Session, Pending Acknowledgment, and the Deduplication Set. Each contact comes back without a new link, and the restored side's next Message to an accepted contact starts a new Session.

## Alternatives

- Restore Sessions too: the restored Device would encrypt new Messages with message keys its old copy already used.
- Drop the contacts too: every contact would need a new link, and every open request would be lost.
