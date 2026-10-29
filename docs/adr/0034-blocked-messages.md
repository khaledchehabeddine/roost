# Blocked Messages

Roost still authenticates a blocked contact's Messages and advances the Session's receive state, so the Session keeps working if the contact is unblocked, but it withholds their plaintext. It still records the consent a Message carries, such as a Contact Request that crosses this side's own, so the contact is accepted after an unblock. By default Roost returns no acknowledgment, so the blocked contact can't tell a block from an offline recipient. An opt-in setting returns one, which tells the blocked contact the Message arrived.
