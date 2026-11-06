# Reconnecting After a Rotation

The relay finds a prekey bundle only by discovery key and never says where a rotated inbox went. So after a contact rotates without its new inbox grant reaching this side, such as during a block, only a fresh contact link reconnects the two. Any bundle whose discovery key is newer than the stored one starts a new session, whichever side opens the link.

## Alternatives

- Let the relay find a contact's current inbox by identity key: anyone who ever knew it, including a blocked contact, could find a rotated inbox, which undoes blocking.
- Have each side leave a sealed note with its new inbox grant at the relay when it rotates: it would reconnect contacts without a link, but it needs new relay storage and a privacy review, so it's left for later.
