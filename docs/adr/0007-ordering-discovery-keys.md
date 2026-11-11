# Ordering Discovery Keys

A contact orders discovery keys by their signed creation time, then by epoch, because restoring an older backup can reuse an epoch number. Each rotation dates its key after the key it replaces, so a clock that moved back can't leave contacts sending to the old inbox. The cost is that dates can run ahead of the real time.

## Alternatives

- Refuse a key dated after the contact's own clock: a contact whose clock is slow would ignore every new key.
