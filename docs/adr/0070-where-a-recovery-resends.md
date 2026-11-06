# Where a Recovery Resends

A recovery never repairs a session. It resends on a session newer than the one the message went out on, either one the contact has delivered on since or a new one from the contact's prekey bundle (ADR 0038), so the contact never has to skip past lost message numbers. If the relay no longer knows the contact's discovery key, the recovery waits for the contact's next inbox grant or session.

## Alternatives

- Resend on whichever session the contact delivered on last: an older session may have lost messages sent on it, which the contact would have to skip past.
- Look up the contact's discovery key before fetching its bundle: the fetch uses up a one-time prekey only when the key is current, and then only a recovery after an unblock leaves the bundle unused.
