# Blocked Messages

Roost withholds a blocked contact's plaintext but still authenticates their messages, advances the session, and records any consent they carry. So the session works again after an unblock, and a crossing contact request still accepts the contact. Roost returns no acknowledgment unless the app asks for one, so the contact can't tell a block from an offline recipient.
