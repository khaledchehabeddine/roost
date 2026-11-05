# Recovering After a Newer Inbox Grant

The Relay redelivers a Message it admitted until the recipient saves it, so a Recovery usually waits out a quiet period (ADR 0043). A contact's newer Inbox Grant skips that wait, because the Relay answers a dead Delivery Capability as if it admitted the Message. Core then signals a Recovery at once for the unacknowledged Messages sent to an older inbox, which encrypts them again on a fresh Session (ADR 0070).

## Alternatives

- Wait out the quiet period here too: Messages sent to a dead inbox can never arrive, so waiting only delays their resend.
- Resend the original bytes to the new inbox: a contact that restored a backup no longer has the Session to open them, and Roost would have to keep a copy of every unacknowledged Message.
