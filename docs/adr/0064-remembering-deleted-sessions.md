# Remembering Deleted Sessions

When Roost deletes a Session, it remembers the SessionID until the Session's signed prekey expires, so a replayed first Message can't revive the Session and pull outgoing Messages onto it. Those records are limited per contact too, so a contact who churns Sessions on purpose can only lose their own.

## Alternatives

- Keep many older Sessions, as Signal does: it catches the same replays but stores whole Sessions instead of their IDs.
