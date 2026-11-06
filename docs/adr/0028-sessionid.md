# Session ID

Both peers derive the session ID from the X3DH secret, so only they can compute it and each handshake gets its own. It addresses the session's state and travels with each message in either direction, and a message naming a known session ID uses that session and never replaces it. An unknown ID creates a session only when the message's handshake derives it, so a made-up ID can't create a session, trigger an acknowledgment, or start recovery.

## Alternatives

- Let the initiator choose the ID: a faulty or hostile initiator could reuse one.
- A separate ID for each direction: it only hides links from someone holding both peers' discovery keys, who can already link the directions by timing.
