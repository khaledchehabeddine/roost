# Recovery Probes

A recovery may turn out unneeded, and resending a contact's whole backlog each time would flood its inbox with copies and fill the relay's queue for first messages. So a recovery that starts a new session resends only the oldest unacknowledged message, the probe, and sends the rest once the contact acknowledges it, moving them to the probe's session if it deletes the one they went out on. A recovery onto a newer session the contact delivered on resends everything at once, even with a probe out, as ordinary messages, because the contact just proved it's reachable there.

## Alternatives

- Resend everything on each recovery: a contact offline for a week would come back to several copies of every message.
