# Blocking by Rotating the Inbox

Blocking rotates the inbox, even for a stranger, and withholds the new inbox grant from the blocked contact. A new inbox stops a blocked person from returning under a new identity, because the relay finds an inbox only by its discovery key and never says where a rotated one went. The cost is that a contact who missed a rotation's new grant, such as during a block, reconnects only through a new contact link.

## Alternatives

- Let the relay find an inbox by identity key: anyone who ever knew it, including a blocked contact, could find a rotated inbox, which undoes blocking.
