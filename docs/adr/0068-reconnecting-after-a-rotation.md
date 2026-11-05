# Reconnecting After a Rotation

The Relay finds a prekey bundle only by Discovery Key and never says where a rotated inbox went. So after a contact rotates without its new Inbox Grant reaching this side, such as during a block, only a fresh contact link reconnects the two. Any bundle whose Discovery Key is newer than the stored one starts a new Session, whichever side opens the link.

## Alternatives

- Let the Relay find a contact's current inbox by Identity Key: anyone who ever knew it, including a blocked contact, could find a rotated inbox, which undoes blocking.
- Have each side leave a sealed note with its new Inbox Grant at the Relay when it rotates: it would reconnect contacts without a link, but it needs new Relay storage and a privacy review, so it's left for later.
