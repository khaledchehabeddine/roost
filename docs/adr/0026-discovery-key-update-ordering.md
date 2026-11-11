# Discovery Key Update Ordering

Restoring an older backup continues from that backup's epoch, so two different discovery keys can share an epoch number. A contact update therefore accepts a discovery key only if its signed creation time is later, or the same with a higher epoch. Each device dates its rotations to keep this order when its own clock moves back (ADR 0083).

## Alternatives

- Refuse a key dated after the contact's own clock: a contact whose clock is slow would ignore every new key.
