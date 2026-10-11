# X3DH Handshake

A Session starts with X3DH against the recipient's current Discovery Key, signed prekey, and a one-time prekey when one is left. The sender's identity travels only in the first message's innermost layer, so a leaked Discovery Key alone doesn't reveal it, and Roost reveals it to the app before the app accepts the Session. Only people an Identity messages learn its Identity Key, and rotating the Discovery Key changes who can reach an Identity, not who can recognize it.

## Alternatives

- Reveal the sender only after the recipient accepts: the first message couldn't prove who sent it, so Roost couldn't check the certificate and the recipient couldn't block the sender.
