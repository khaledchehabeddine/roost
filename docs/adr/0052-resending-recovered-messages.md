# Resending Recovered Messages

Roost keeps no copy of a sent Message, so Recovery encrypts each Message again from the app's copy of its content. The new copy keeps the MessageID and send time, so the contact shows it once and in place, and it replaces the app's queued copy in one commit, so the old bytes are never sent again. The contact may still get the old copy, so an acknowledgment of either copy ends the wait.

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext for as long as a contact stays silent.
- Keep the encrypted copy and resend it: a contact that lost its Session, such as by restoring a backup, couldn't open it.
- Give the resent copy a new MessageID: the contact couldn't tell it from the original and would show it twice.
- Resend Grant Updates too: recovered Messages carry the Inbox Grant (ADR 0068).
- Match an acknowledgment only on its own Session: an acknowledgment of the old copy would match nothing, and the Message would be resent and shown as not delivered.
