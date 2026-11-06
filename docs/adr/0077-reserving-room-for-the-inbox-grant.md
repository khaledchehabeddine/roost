# Reserving Room for the Inbox Grant

A resent message carries the inbox grant even when the original didn't (ADR 0045, ADR 0059), so a message near the size limit couldn't be resent, and every message behind it waited too. So every message's content leaves room for the longest grant, whether or not that copy carries it, and a resend always fits.

## Alternatives

- Resend without the grant when it doesn't fit: a contact that lost its state couldn't acknowledge the probe, so the messages behind it would still wait.
- Raise the largest padding size: older versions would reject the larger messages.
