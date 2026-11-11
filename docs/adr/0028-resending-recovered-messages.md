# Resending Recovered Messages

A recovery encrypts the app's copy of each unacknowledged message again, on a newer session, with the same message ID and send time. The app shows one message per sender and message ID, so the contact sees a resent message once and in place.

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext while a contact stays silent.
- Resend the original bytes: a contact that lost its session couldn't open them.
- Drop resent copies in Roost by message ID: no limit on remembered IDs covers every resend while the relay holds a message.
