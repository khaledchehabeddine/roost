# Unified Sealed-Sender Frame

Session Messages, acknowledgments, and X3DH first messages all use one Sealed Sender Frame, because one format is easier to audit than several. The frame exposes only the routing fields, authenticated against tampering, and encrypts everything else, including the sender and the SessionID. One version on the frame covers every layer inside it, so readers never have to combine versions, and relays forward frames without reading it.

## Alternatives

- Separate formats for Session and X3DH messages: two formats under one version number made it unclear which layout a frame used.
- Encrypt the frame to the recipient's Identity Key: peers find and route to each other through the current Discovery Key.
- A version on each layer: readers would have to handle combinations of versions.
- Separate versions for the visible frame and its sealed contents: this only helps if relays read the version.
