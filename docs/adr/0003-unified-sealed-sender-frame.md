# Unified Sealed Sender Frame

Every message, including first messages and acknowledgments, travels in one sealed sender frame, because one format is easier to audit than several. The frame shows only the authenticated routing fields and encrypts everything else, including the sender and the session ID.

## Alternatives

- Encrypt the frame to the recipient's identity key: peers route to each other through the current discovery key.
