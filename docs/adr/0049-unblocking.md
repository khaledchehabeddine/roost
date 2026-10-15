# Unblocking

Unblocking keeps the contact's Sessions, so the next Message carries the current Inbox Grant over a kept Session without a new handshake, but the contact may have rotated during the block, and the Relay silently drops Messages sent with a dead capability, so the first send after an unblock fetches the contact's prekey bundle to check that its Discovery Key is still current. The Relay finds a bundle only by Discovery Key and never says where a rotated inbox went, so after such a rotation only a fresh contact link reconnects the two, and any bundle whose Discovery Key is newer than the stored one starts a new Session, whichever side opens a link. Acceptance and verification belong to the Identity Key and carry over, and when the contact's request is still open, the new Session's first Message is a Contact Request, which accepts both sides as crossing requests do (ADR 0043), since an acceptance counts only on the requester's Session and that inbox is gone.

## Alternatives

- Always reuse the kept Session: if the contact rotated during the block, both sides' Messages would vanish without either side being told.
- Always start a new Session: every unblock would cost a handshake, even when the contact's inbox hasn't changed.
- Let the Relay find a contact's current inbox by Identity Key: anyone who ever knew it, including a blocked contact, could find a rotated inbox, which undoes blocking.
- Have each side leave a sealed note with its new Inbox Grant at the Relay when it rotates: it would reconnect contacts without a link, but it needs new Relay storage and a privacy review, so it's left for later.
