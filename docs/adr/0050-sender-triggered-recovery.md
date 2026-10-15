# Sender-Triggered Recovery

Roost can't authenticate a Message it fails to decrypt, because the sender is sealed inside the ratchet ciphertext (ADR 0008), so nothing on receive marks a Session dead, and only the sender, whose acknowledgments stop, can tell that a contact lost its Session. Roost signals a recovery once, when the contact starts a newer Session or after a quiet period Roost sets, and the recovery resends on a newer Session the contact has delivered on, or fetches the contact's prekey bundle to start one (ADR 0045), or waits for the contact's next Inbox Grant if the Relay no longer knows its Discovery Key. A contact who is only offline looks the same as one that lost its Session, so the quiet period is long, and a recovery that wasn't needed costs the contact one extra Message (ADR 0051).

## Alternatives

- Mark a Session dead when a Message overflows the skipped-key cap but decrypts with keys derived and then discarded: the gap fills as the earlier Messages arrive, so it would replace Sessions that heal on their own, and it still misses a contact that lost its Session.
- Let the receiver ask the sender to resend, as Signal and WhatsApp do: the receiver can't tell who sent a Message it can't decrypt.
- Keep a marker for unrecoverable Sessions for some future cause: nothing sets it, so it would stay untested.
- Let the app pass the quiet period with each call: the app and its extensions could disagree, as with the limit before acceptance (ADR 0044).
- Look up the contact's Discovery Key before fetching its bundle: the fetch uses up a one-time prekey only when the key is current, and the recovery then needs the bundle anyway.
