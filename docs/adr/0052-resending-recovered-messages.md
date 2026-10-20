# Resending Recovered Messages

Roost keeps only a sent Message's encrypted copy, which a contact that lost its Session can't open, so recovery encrypts each Message again from the app's copy of its content. The new copy keeps the MessageID, kind, and send time, so the contact shows it once and in place. It replaces the old copy in one commit, so the old bytes are never sent again, and Grant Updates aren't resent, because recovered Messages carry the Inbox Grant (ADR 0068).

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext for as long as a contact stays silent.
- Resend the old bytes: a contact that lost its Session still couldn't open them.
- Give the resent copy a new MessageID: the contact couldn't tell it from the original and would show it twice.
