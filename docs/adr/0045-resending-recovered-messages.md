# Resending Recovered Messages

Roost keeps no copy of a sent message, so recovery encrypts each message again from the app's copy of its content. The new copy keeps the message ID and send time, so the contact shows it once and in place, and it replaces the app's queued copy in one commit, so the old bytes are never sent again. The contact may still get the old copy, so an acknowledgment of either copy ends the wait.

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext for as long as a contact stays silent.
- Keep the encrypted copy and resend it: a contact that lost its session, such as by restoring a backup, couldn't open it.
- Give the resent copy a new message ID: the contact couldn't tell it from the original and would show it twice.
- Resend grant updates too: recovered messages carry the inbox grant (ADR 0059).
- Match an acknowledgment only on its own session: an acknowledgment of the old copy would match nothing, and the message would be resent and shown as not delivered.
