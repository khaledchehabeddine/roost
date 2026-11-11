# Blocked Messages

Roost withholds a blocked contact's plaintext but still authenticates their messages and advances the session, so the session works again after an unblock. It returns no acknowledgment unless the app asks for one, so the contact can't tell a block from an offline recipient.
