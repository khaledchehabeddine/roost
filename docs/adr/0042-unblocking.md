# Unblocking

Unblocking keeps the contact's Sessions, so the next Message to an accepted contact carries the current Inbox Grant over a kept Session without a new handshake. The contact may have rotated during the block, and the Relay silently drops Messages sent with a dead capability. So the first send after an unblock fetches the contact's prekey bundle to check that its Discovery Key is still current.

## Alternatives

- Always reuse the kept Session: if the contact rotated during the block, both sides' Messages would vanish without either side being told.
- Always start a new Session: every unblock would cost a handshake, even when the contact's inbox hasn't changed.
