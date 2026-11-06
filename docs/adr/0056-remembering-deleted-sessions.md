# Remembering Deleted Sessions

When Roost deletes a session this side accepted, it remembers the session ID until the session's signed prekey expires, so a replayed first message can't revive the session and pull outgoing messages onto it. Those records are limited per contact too, so a contact who churns sessions on purpose can only lose their own.

## Alternatives

- Keep many older sessions, as Signal does: it catches the same replays but stores whole sessions instead of their IDs.
