# Encoding Contact Publications

An app's iOS and Android versions must put the same contact publication in a contact link, so Roost encodes and decodes it. It holds only the identity key, the current discovery key, and the signatures that bind them, which is all a peer needs to fetch the prekey bundle and verify it. Decoding verifies every signature and records nothing, so an app can check a link before anyone asks (ADR 0061).

## Alternatives

- Let each platform encode the publication: links from iOS and Android could drift apart, and each platform would verify the signatures its own way.
- Include the signed prekey, so a link could start a session without the relay: Roost replaces the signed prekey on a schedule (ADR 0018), so most links would carry a stale one.
- Include the inbox grant: anyone who sees the link would hold the delivery capability, which Roost shares only with contacts and never with the app (ADR 0035).
