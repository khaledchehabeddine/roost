# Where a Recovery Resends

A recovery never repairs a Session. It resends on a newer Session the contact has delivered on, or else fetches the contact's prekey bundle to start one (ADR 0045). If the Relay no longer knows the contact's Discovery Key, it waits for the contact's next Inbox Grant.

## Alternatives

- Look up the contact's Discovery Key before fetching its bundle: the fetch uses up a one-time prekey only when the key is current, and the recovery then needs the bundle anyway.
