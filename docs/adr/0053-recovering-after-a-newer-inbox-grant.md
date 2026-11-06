# Recovering After a Newer Inbox Grant

The relay redelivers a message it admitted until the recipient saves it, so a recovery usually waits out a quiet period (ADR 0043). A contact's newer inbox grant skips that wait, because the relay answers a dead delivery capability as if it admitted the message. Core then signals a recovery at once for the unacknowledged messages sent to an older inbox, which encrypts them again on a fresh session (ADR 0070).

## Alternatives

- Wait out the quiet period here too: messages sent to a dead inbox can never arrive, so waiting only delays their resend.
- Resend the original bytes to the new inbox: a contact that restored a backup no longer has the session to open them, and Roost would have to keep a copy of every unacknowledged message.
