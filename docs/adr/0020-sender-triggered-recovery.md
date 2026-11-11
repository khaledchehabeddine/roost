# Sender-Triggered Recovery

Roost can't authenticate a message it fails to decrypt, because the sender is sealed inside the ratchet ciphertext, so only the sender, whose acknowledgments stop, can tell that a contact lost its session. Roost signals a recovery once the contact delivers on a newer session, sends a newer inbox grant, or leaves messages unacknowledged through a long quiet period. The quiet period is long because a contact who is only offline looks the same.

## Alternatives

- Let the receiver ask the sender to resend, as Signal and WhatsApp do: the receiver can't tell who sent a message it can't decrypt.
- Wait out the quiet period after a newer inbox grant too: the relay answers a dead delivery capability as if it admitted the message, so messages sent to the old inbox can never arrive.
