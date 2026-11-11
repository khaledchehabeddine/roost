# Ordering Discovery Keys

A contact orders discovery keys by their signed creation time, then by epoch, because restoring an older backup can reuse an epoch number. Each rotation dates its key after the key it replaces, so a clock that moved back can't make contacts ignore the new key. The cost is that dates can run ahead of the real time.

## Alternatives

- Date each key by the clock alone: after an ordinary clock correction, contacts would keep sending to an inbox that no longer exists.
- Refuse a key dated after the contact's own clock: a contact whose clock is slow would ignore every new key.
