# Encoding Contact Publications

An app's iOS and Android versions must put the same Contact Publication in a contact link, so Roost encodes and decodes it. It holds only the Identity Key, the current Discovery Key, and the signatures that bind them, which is all a peer needs to fetch the prekey bundle and verify it. Decoding verifies every signature and records nothing, so an app can check a link before anyone asks (ADR 0070).

## Alternatives

- Let each platform encode the publication: links from iOS and Android could drift apart, and each platform would verify the signatures its own way.
- Include the signed prekey, so a link could start a Session without the Relay: Roost replaces the signed prekey every week, so most links would carry a stale one.
- Include the Inbox Grant: anyone who sees the link would hold the Delivery Capability, which Roost shares only with contacts and never with the app (ADR 0042).
- Read Android's earlier link layout: v0.16 starts fresh, so no earlier link has to keep working.
