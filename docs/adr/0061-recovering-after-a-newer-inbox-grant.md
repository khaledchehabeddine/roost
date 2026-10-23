# Recovering After a Newer Inbox Grant

The Relay redelivers a Message it accepted until the recipient saves it, so the app doesn't resend accepted Messages. The exception is a contact's newer Inbox Grant, because the Relay answers a dead Delivery Capability as if it queued the Message. Core then signals a recovery at once, which encrypts the contact's unacknowledged Messages again on a fresh Session (ADR 0079).

## Alternatives

- Keep Pending Acknowledgments in memory: every Library Instance must see them, even after a restart.
- Resend unacknowledged Messages on a timer: the Relay already redelivers, so timed resends only add copies.
- Resend the original bytes to the new inbox: a contact that restored a backup no longer has the Session to open them, and Roost would have to keep a copy of every unacknowledged Message.
