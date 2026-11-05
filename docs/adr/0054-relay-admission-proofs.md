# Relay Admission Proofs

The Relay admits only First Messages that name its current signed prekey, so a First Message for an old one must have arrived before the rotation. KeyStore uses an old signed prekey only after the app proves the Relay admitted that exact First Message against it. The proof guards what the app passes to Roost, not against the Relay, because Roost relies on the Relay for admission and availability but never for confidentiality or authenticity.

## Alternatives

- Compare the Relay's admission time with the time a signed prekey was replaced: the Device and the Relay keep different clocks, and the Relay learns of a rotation only when the new prekey is uploaded.
- Accept any First Message for a kept signed prekey: anyone holding a leaked old prekey could forge First Messages until it expired.
- Verify the Relay's admission proof inside Roost: Roost would have to parse the Relay's formats.
