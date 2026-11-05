# Revealing the Sender in a First Message

The sender's identity travels only in a First Message's innermost layer, so a leaked Discovery Key alone doesn't reveal it, and Roost reveals it to the app before the app accepts the Session.

## Alternatives

- Reveal the sender only after the recipient accepts: the First Message couldn't prove who sent it, so Roost couldn't check the certificate and the recipient couldn't block the sender.
