# Session ID

Both peers derive the session ID from the X3DH secret, so only they can compute it. A message with an unknown ID creates a session only when its handshake derives that ID, so a made-up ID can't create a session, trigger an acknowledgment, or start a recovery.

## Alternatives

- Let the initiator choose the ID: a faulty or hostile initiator could reuse one.
