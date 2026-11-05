# Recovery Probes

A Recovery may turn out unneeded, and resending a contact's whole backlog each time would flood its inbox with copies and fill the Relay's queue for First Messages. So a Recovery that starts a new Session resends only the oldest unacknowledged Message, the Probe, and sends the rest once the contact acknowledges it, moving them to the Probe's Session if it deletes the one they went out on. A Recovery onto a newer Session the contact delivered on resends everything at once, as ordinary Messages, because the contact just proved it's reachable there.

## Alternatives

- Resend everything on each Recovery: a contact offline for a week would come back to several copies of every Message.
