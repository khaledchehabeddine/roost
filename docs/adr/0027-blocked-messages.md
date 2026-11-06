# Blocked Messages

Roost still authenticates a blocked contact's messages, advances the session's receive state, and records any consent they carry, so the session keeps working after an unblock and a crossing contact request still accepts the contact, but it withholds their plaintext. Unless the app asks for an acknowledgment, which tells the blocked contact the message arrived, Roost returns none, so the contact can't tell a block from an offline recipient.
