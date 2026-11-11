# Resending Recovered Messages

Roost keeps no copy of a sent message, so a recovery encrypts the app's copy of each message again. It resends on a session newer than the one the message went out on, so the contact never has to skip past lost message numbers. The new copy keeps the message ID and send time, and the app shows one message per sender and message ID, so the contact sees it once and in place.

## Alternatives

- Keep the content in Roost until it's acknowledged: stored state would hold plaintext for as long as a contact stays silent.
- Resend the original bytes: a contact that lost its session, such as by restoring a backup, couldn't open them.
- Have Roost remember recent message IDs to drop resent copies: it would need a limit, and no limit covers every resend while the relay holds a message.
