# Handshake Until First Reply

As in Signal, every Message an initiator sends on a new Session carries the handshake until a reply arrives, or for a Contact Request until the peer accepts (ADR 0065), so a lost or late first Message doesn't block the ones after it. The recipient looks up the Message's SessionID first and runs X3DH only for a Session it doesn't have yet. The cost is larger Messages until the first reply, and the Relay can tell which Messages carry a handshake.

## Alternatives

- Send the handshake only in the first Message: a lost or late first Message would leave every later Message undecryptable until the app resent it.
