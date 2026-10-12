# Handshake Until First Reply

Until the initiator receives a reply, every Message it sends on a new Session carries the handshake and the SessionID, as in Signal, so a lost or late first message doesn't block the Messages after it. The recipient looks up the SessionID first and runs X3DH only for a Session it doesn't have yet. The cost is larger Messages until the first reply, and the relay can tell which Messages carry a handshake.

## Alternatives

- Send the handshake only in the first message: a lost or late first message would leave every later Message undecryptable until the app resent it.
