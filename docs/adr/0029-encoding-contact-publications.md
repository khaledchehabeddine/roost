# Encoding Contact Publications

An app's iOS and Android versions must put the same contact publication in a contact link, so Roost encodes and decodes it. The publication holds only the identity key, the current discovery key, and the signatures that bind them, which is all a peer needs to fetch and verify the prekey bundle. Decoding checks every signature and records nothing, so an app can check a link before anyone sends a contact request.

## Alternatives

- Include the signed prekey, so a link could start a session without the relay: Roost replaces the signed prekey on a schedule, so most links would carry a stale one.
- Include the inbox grant: anyone who sees the link would hold the delivery capability, which Roost shares only with contacts.
