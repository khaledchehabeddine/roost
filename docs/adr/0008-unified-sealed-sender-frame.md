# Unified Sealed Sender Frame

Established messages, acknowledgments, and first messages all use one sealed sender frame, because one format is easier to audit than several. The frame exposes only the routing fields, authenticated against tampering, and encrypts everything else, including the sender and the session ID.

## Alternatives

- Separate formats for established and first messages: two formats under one version number made it unclear which layout a frame used.
- Encrypt the frame to the recipient's identity key: peers find and route to each other through the current discovery key.
