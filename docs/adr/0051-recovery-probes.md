# Recovery Probes

A recovery may turn out unneeded, and resending a contact's whole backlog each time would flood its inbox with copies and fill the Relay's queue for first Messages. So a recovery that starts a new Session resends only the oldest unacknowledged Message, and sends the rest once the contact acknowledges it. A recovery onto a newer Session the contact delivered on resends everything at once, as ordinary Messages, because the contact just proved it's reachable there.

## Alternatives

- Resend everything on each recovery: a contact offline for a week would come back to several copies of every Message.
