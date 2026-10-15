# Unblocking

Unblocking keeps the contact's Sessions, so the next Message carries the current Inbox Grant over a kept Session without a new handshake. The contact may have rotated its own inbox during the block, when its grant couldn't reach this inbox, and the Relay silently drops Messages sent with a dead capability, so the first send after an unblock asks for the contact's current prekey bundle and starts a new Session only if its Discovery Key is newer than the stored one.

## Alternatives

- Always reuse the kept Session: if the contact rotated during the block, both sides' Messages would vanish without either side being told.
- Always start a new Session: every unblock would cost a handshake, even when the contact's inbox hasn't changed.
