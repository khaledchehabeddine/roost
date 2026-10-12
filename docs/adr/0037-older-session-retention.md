# Older Session Retention

A peer keeps Sessions it no longer sends on, so Messages already on their way to them still decrypt, but only a fixed number per contact, deleting the oldest beyond that, so a contact who keeps starting Sessions can't grow storage. When Roost deletes a Session, it remembers the SessionID until the signed prekey the Session used expires, so a replayed first message can't bring the Session back and pull the recipient's outgoing Messages onto it. Those records are also limited per contact, so a contact who churns Sessions on purpose can only lose their own.

## Alternatives

- Delete older Sessions after a set time without a Message: a contact who keeps starting Sessions could grow storage without limit, and Roost would need the app to supply the time.
- Keep many older Sessions, as Signal does: it catches the same replays but stores whole Sessions instead of their IDs.
