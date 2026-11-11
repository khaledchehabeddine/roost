# Messages Before Acceptance

Before acceptance, each side may send a few messages, so people can check who they're talking to. Each side counts the distinct message IDs it sends and receives, refuses to send past Roost's limit, and withholds the plaintext of messages that arrive past it. Sealed sender hides the sender from the relay, so only the recipient can enforce the limit.

## Alternatives

- Count both directions together: a lost or late message would make the sides disagree on when the limit applies.
- Let the app set the limit: two apps could disagree on it.
