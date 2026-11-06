# Relay Admission Proofs

The relay admits only first messages that name its current signed prekey, so a first message for an old one must have arrived before the rotation. KeyStore uses an old signed prekey only after the app proves the relay admitted that exact first message against it. The proof guards what the app passes to Roost, not against the relay, because Roost relies on the relay for admission and availability but never for confidentiality or authenticity.

## Alternatives

- Compare the relay's admission time with the time a signed prekey was replaced: the device and the relay keep different clocks, and the relay learns of a rotation only when the new prekey is uploaded.
- Accept any first message for a kept signed prekey: anyone holding a leaked old prekey could forge first messages until it expired.
- Verify the relay's admission proof inside Roost: Roost would have to parse the relay's formats.
