# Unblocking

Unblocking keeps the contact's sessions, so the next message to an accepted contact carries the current inbox grant over a kept session without a new handshake. The contact may have rotated during the block, and the relay silently drops messages sent with a dead capability. So the first send after an unblock fetches the contact's prekey bundle to check that its discovery key is still current.

## Alternatives

- Always reuse the kept session: if the contact rotated during the block, both sides' messages would vanish without either side being told.
- Always start a new session: every unblock would cost a handshake, even when the contact's inbox hasn't changed.
