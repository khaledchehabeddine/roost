# Blocked Messages

Roost still authenticates a blocked contact's Messages, advances the Session's receive state, and records any consent they carry, so the Session keeps working after an unblock and a crossing Contact Request still accepts the contact, but it withholds their plaintext. Unless the app asks for an acknowledgment, which tells the blocked contact the Message arrived, Roost returns none, so the contact can't tell a block from an offline recipient.
