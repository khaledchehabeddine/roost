# Where a Recovery Resends

A recovery never repairs a Session. It resends on a Session newer than the one the Message went out on, so the contact never has to skip past lost Message numbers: one the contact has delivered on since, or else a new one from the contact's prekey bundle (ADR 0045). If the Relay no longer knows the contact's Discovery Key, it waits for the contact's next Inbox Grant.

## Alternatives

- Resend on whichever Session the contact delivered on last: an older Session may have lost Messages sent on it, which the contact would have to skip past.
- Look up the contact's Discovery Key before fetching its bundle: the fetch uses up a one-time prekey only when the key is current, and the recovery then needs the bundle anyway.
