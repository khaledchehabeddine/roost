# Message Evidence Bundles

A Backend must verify a reported Message without Session state, so receiving a Message in an established Session also returns its Evidence Bundle. The Backend's verifier checks the Sender Certificate as of when the Message was accepted, ignoring later revocations, and returns an Evidence Identity so each Message counts once. Receive rejects any Message whose bundle wouldn't verify, so every accepted Message has a valid bundle.

## Alternatives

- Export the signatures and let each consumer rebuild the transcript: the Rust, Swift, Kotlin, and Backend versions could drift apart.
- Add a recipient signature proving acceptance: it needs another key, and only the sender must be proven.
- Check current revocations: a later revocation doesn't change whether the Message was authentic when accepted.
- Count by MessageID or by bundle bytes: the sender picks the ID, and the bytes can change while the Message stays the same.
