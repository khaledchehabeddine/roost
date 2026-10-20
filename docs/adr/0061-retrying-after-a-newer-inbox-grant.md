# Retrying After a Newer Inbox Grant

The Relay redelivers a Message it accepted until the recipient saves it, so the app doesn't resend accepted Messages. The exception is a contact's newer Inbox Grant, because the Relay answers a dead Delivery Capability as if it queued the Message. Core then returns Retry Instructions with the contact's current destination and the original bytes, which the contact can still open (ADR 0048).

## Alternatives

- Keep Pending Acknowledgments in memory: every Library Instance must see them, even after a restart.
- Resend unacknowledged Messages on a timer: the Relay already redelivers, so timed resends only add copies.
- Reuse the first send's destination on a resend: after the contact rotates, the Relay drops every resend without saying so.
