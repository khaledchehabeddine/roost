# Encrypted Acknowledgments and Retries

An Acknowledgment Artifact is an encrypted Session Message that Core returns for the app to send, so servers in between can't see what was delivered, and it goes through the same decryption and sender checks as other Messages, because the app can't tell them apart before decrypting. Core picks where its own acknowledgment goes only after it authenticates the sender and applies block policy, then asks the app for that destination's Transport Binding, because the route the incoming Message arrived on may not reach the sender. The app doesn't resend a Message the Relay accepted, since the Relay redelivers until the recipient saves it, except after a contact's newer Inbox Grant arrives, because the Relay answers a dead Delivery Capability as if it queued the Message, so Core then returns Retry Instructions with the contact's current destination and the original bytes, which the contact can still open (ADR 0048).

## Alternatives

- Keep Pending Acknowledgments in memory: every Library Instance must see them, even after a restart.
- A separate call for incoming acknowledgments: the app would need to tell them apart before decrypting, and their sender checks could drift from other Messages'.
- Let the app pick the acknowledgment's destination up front: it would choose before Roost knows who sent the Message or whether they're blocked.
- Resend unacknowledged Messages on a timer: the Relay already redelivers, so timed resends only add copies.
- Reuse the first send's destination on a resend: after the contact rotates, the Relay drops every resend without saying so.
