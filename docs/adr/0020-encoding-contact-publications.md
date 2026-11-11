# Encoding Contact Publications

Roost encodes contact publications, so an app's iOS and Android versions put the same one in a contact link. A publication holds only the identity key, the current discovery key, and their binding signatures, which is all a peer needs to fetch and verify the prekey bundle.

## Alternatives

- Include the signed prekey: Roost replaces it on a schedule, so most links would carry a stale one.
- Include the inbox grant: anyone who sees the link could deliver to the inbox.
