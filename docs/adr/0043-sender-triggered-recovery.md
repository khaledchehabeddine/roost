# Sender-Triggered Recovery

Roost can't authenticate a Message it fails to decrypt, because the sender is sealed inside the ratchet ciphertext (ADR 0008), so nothing on receive marks a Session dead. Only the sender, whose acknowledgments stop, can tell that a contact lost its Session, so Roost signals a Recovery once the contact delivers on a newer Session, sends a newer Inbox Grant, or a quiet period passes. A contact who is only offline looks the same, so the quiet period is long, and an unneeded Recovery costs the contact one extra Message (ADR 0044).

## Alternatives

- Mark a Session dead when a Message overflows the skipped-key cap but decrypts with keys derived and then discarded: the gap fills as the earlier Messages arrive, so it would replace Sessions that heal on their own, and it still misses a contact that lost its Session.
- Let the receiver ask the sender to resend, as Signal and WhatsApp do: the receiver can't tell who sent a Message it can't decrypt.
- Keep a marker for unrecoverable Sessions for some future cause: nothing sets it, so it would stay untested.
- Let the app pass the quiet period with each call: the app and its extensions could disagree, as with the limit before acceptance (ADR 0037).
