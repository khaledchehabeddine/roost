# Revealing the Sender in a First Message

The sender's identity travels only in a first message's innermost layer, so a leaked discovery key alone doesn't reveal it, and Roost reveals it to the app before the app accepts the session.

## Alternatives

- Reveal the sender only after the recipient accepts: the first message couldn't prove who sent it, so Roost couldn't check the certificate and the recipient couldn't block the sender.
