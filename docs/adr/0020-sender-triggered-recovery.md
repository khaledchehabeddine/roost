# Sender-Triggered Recovery

Only the sender can notice a lost session, so Roost signals a recovery on the sender's side after a long period without acknowledgments. It signals at once when the contact delivers on a newer session or sends a newer inbox grant. The period is long because a contact who is only offline looks the same.

## Alternatives

- Let the receiver ask the sender to resend, as Signal and WhatsApp do: the ratchet ciphertext hides the sender, so the receiver can't tell who sent a message it can't decrypt.
- Wait out the period after a newer inbox grant too: the relay answers messages sent with a dead delivery capability as if it admitted them, so they never arrive.
