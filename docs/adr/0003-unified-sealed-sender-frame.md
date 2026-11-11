# Unified Sealed Sender Frame

First messages, established messages, and acknowledgments all travel in one sealed sender frame, because one format is easier to audit than several. The frame shows only the routing fields, authenticated against tampering, and encrypts everything else, including the sender and the session ID. So neither the relay nor the app can tell an acknowledgment from other messages before Roost decrypts it.

## Alternatives

- Encrypt the frame to the recipient's identity key: peers find and route to each other through the current discovery key.
