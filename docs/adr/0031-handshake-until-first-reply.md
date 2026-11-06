# Handshake Until First Reply

As in Signal, every message an initiator sends on a new session carries the handshake until a reply arrives, or for a contact request until the peer accepts (ADR 0057), so a lost or late first message doesn't block the ones after it. The recipient looks up the message's session ID first and runs X3DH only for a session it doesn't have yet. The cost is larger messages until the first reply, and the relay can tell which messages carry a handshake.

## Alternatives

- Send the handshake only in the first message: a lost or late first message would leave every later message undecryptable until the app resent it.
