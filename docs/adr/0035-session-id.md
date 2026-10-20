# Session ID

Both peers derive the SessionID from the X3DH secret, so only they can compute it and each handshake gets its own. It addresses the Session's state and travels with each Message in either direction, and a Message naming a known SessionID uses that Session and never replaces it. An unknown ID creates a Session only when the Message's handshake derives it, so a made-up ID can't create a Session, trigger an acknowledgment, or start recovery.

## Alternatives

- Hash the handshake's public keys: anyone holding the recipient's Discovery Key could compute the ID from the first Message alone.
- Let the initiator choose the ID: a faulty or hostile initiator could reuse one.
- A separate ID for each direction: it only hides links from someone holding both peers' Discovery Keys, who can already link the directions by timing.
