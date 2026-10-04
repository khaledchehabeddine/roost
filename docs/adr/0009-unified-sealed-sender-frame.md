# Unified Sealed-Sender Frame

Session Messages, acknowledgments, and X3DH first messages all use one Sealed Sender Frame, because one format is easier to audit than several. The frame exposes only the routing fields, authenticated against tampering, and encrypts everything else, including the sender. Transports can route a Message without learning who sent it or what it says.

## Alternatives

- Separate formats for Session and X3DH messages: two formats under one version number made it unclear which layout a frame used.
- Encrypt the frame to the recipient's Identity Key: peers find and route to each other through the current Discovery Key.
