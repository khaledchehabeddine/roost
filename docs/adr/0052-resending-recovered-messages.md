# Resending Recovered Messages

Roost keeps only the encrypted copy of a sent Message, and a contact that lost its Session can't open those bytes, so recovery encrypts each Message again from the app's copy of its content, keeping its MessageID, kind, and send time so the contact shows it once and in place. One commit replaces the old encrypted copy and its resend work with the new ones, so the old bytes are never sent again, and the app tracks the recovery as a job of its own, because its record of the original send already says it's done. Grant Updates aren't resent, because the recovered Messages carry the Inbox Grant (ADR 0042).

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext for as long as a contact stays silent.
- Resend the old bytes: a contact that lost its Session still couldn't open them.
- Give the resent copy a new MessageID: the contact couldn't tell it from the original and would show it twice.
