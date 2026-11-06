# Sender-Triggered Recovery

Roost can't authenticate a message it fails to decrypt, because the sender is sealed inside the ratchet ciphertext (ADR 0008), so nothing on receive marks a session dead. Only the sender, whose acknowledgments stop, can tell that a contact lost its session, so Roost signals a recovery once the contact delivers on a newer session, sends a newer inbox grant, or a quiet period passes. A contact who is only offline looks the same, so the quiet period is long, and an unneeded recovery costs the contact one extra message (ADR 0044).

## Alternatives

- Mark a session dead when a message overflows the skipped-key cap but decrypts with keys derived and then discarded: the gap fills as the earlier messages arrive, so it would replace sessions that heal on their own, and it still misses a contact that lost its session.
- Let the receiver ask the sender to resend, as Signal and WhatsApp do: the receiver can't tell who sent a message it can't decrypt.
- Keep a marker for unrecoverable sessions for some future cause: nothing sets it, so it would stay untested.
- Let the app pass the quiet period with each call: the app and its extensions could disagree, as with the limit before acceptance (ADR 0037).
