# Recovery Probes

A recovery may turn out unneeded, and resending a contact's whole backlog each time would flood its inbox with copies and fill the Relay's queue for first Messages, so a recovery that starts a new Session resends only the oldest unacknowledged Message and sends the rest once the contact acknowledges it. A probe that stays unacknowledged gets the recovery check again after a longer wait, and Messages still unacknowledged once the Relay would have dropped them, or once their Session is deleted, show as not delivered, so nothing waits forever and the app always knows what didn't arrive. A recovery onto a Session the contact started resends everything at once, because the contact just proved it's reachable there, and those Messages travel as ordinary Messages, not first Messages.

## Alternatives

- Resend everything on each recovery: a contact offline for a week would come back to several copies of every Message.
- Recover only once until the contact writes: a probe lost to another rotation would stay stuck until the contact wrote.
- Keep recovering until the contact answers: a contact who left for good would hold unacknowledged Messages forever, and enough of them would block sending to that contact.
