# Session ID

Both peers derive the SessionID from the X3DH secret, instead of the app picking a value both had to match, and it is both the Session's state address and the ID each Message carries in either direction. Only the two peers can compute it, and distinct handshakes get distinct IDs. A Message naming a known SessionID uses that Session and never replaces it, and otherwise only a handshake whose X3DH derives that same ID can create one, so a made-up ID can't create a Session, trigger an acknowledgment, or start recovery.

## Alternatives

- Hash the handshake's public keys: anyone holding the recipient's Discovery Key could compute the ID from the first message alone.
- Let the initiator choose the ID: a faulty or hostile initiator could reuse one.
- A separate ID for each direction: it only hides links from someone holding both peers' Discovery Keys, who can already link the directions by timing.
