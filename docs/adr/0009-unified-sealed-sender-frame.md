# Unified Sealed Sender Frame

Established Messages, acknowledgments, and First Messages all use one Sealed Sender Frame, because one format is easier to audit than several. The frame exposes only the routing fields, authenticated against tampering, and encrypts everything else, including the sender and the SessionID.

## Alternatives

- Separate formats for Established and First Messages: two formats under one version number made it unclear which layout a frame used.
- Encrypt the frame to the recipient's Identity Key: peers find and route to each other through the current Discovery Key.
