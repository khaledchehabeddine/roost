# Accepting a Request After a Restore

A restore drops the requester's Session, the only one an acceptance counts on (ADR 0043). So accepting a request the backup kept starts a new Session whose first Message is a Contact Request, which accepts both sides as crossing requests do. With the Session gone, Roost can tell only whether the contact wrote at all, so for a contact that did, it takes the app's acceptance as the answer to who asked.

## Alternatives

- Refuse the acceptance until the requester writes again: the requester can't tell the restore happened, so the request would stay open on both sides.
