# Dating Discovery Keys After the Ones They Replace

Contacts keep the discovery key with the later creation time (ADR 0026), so a rotation dated by a clock that moved back would be ignored. Each rotation therefore dates its key after the key it replaces, as long as the identity signed that key. The cost is that dates can run ahead of the real time.

## Alternatives

- Date each key by the clock alone: after an ordinary clock correction, contacts would keep sending to an inbox that no longer exists.
- Give the new key the replaced key's date and let the epoch break the tie: a restored backup can repeat an epoch, so the date alone should order one device's keys.
