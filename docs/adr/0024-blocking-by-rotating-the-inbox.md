# Blocking by Rotating the Inbox

Blocking rotates the inbox, even for a stranger, and withholds the new inbox grant from the blocked person. The relay finds an inbox only by its discovery key, so they can't find the new one, even under a new identity. The cost is that any contact who missed a new grant, such as during a block, reconnects only through a new contact link.

## Alternatives

- Let the relay find an inbox by identity key: anyone who ever knew it, including a blocked contact, could find the new inbox.
