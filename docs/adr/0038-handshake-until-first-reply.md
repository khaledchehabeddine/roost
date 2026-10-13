# Handshake Until First Reply

Until the initiator receives a reply, or for a Contact Request until the peer accepts it, every Message it sends on a new Session carries the handshake and the SessionID, as in Signal, so a lost or late first message doesn't block the Messages after it, and a requester without the peer's Delivery Capability can still reach its inbox. The recipient looks up the SessionID first and runs X3DH only for a Session it doesn't have yet. The cost is larger Messages until the first reply or acceptance, and the relay can tell which Messages carry a handshake.

## Alternatives

- Send the handshake only in the first message: a lost or late first message would leave every later Message undecryptable until the app resent it.
- End a request's handshake at the first reply: the requester couldn't reach the peer's inbox until the peer accepted.
