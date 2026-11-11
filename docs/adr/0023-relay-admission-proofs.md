# Relay Admission Proofs

The relay admits only first messages that name the current signed prekey, so a first message for an old one must have arrived before the rotation. Roost opens a first message with an old signed prekey only after the app proves the relay admitted that exact message against it. The proof guards what the app passes to Roost, not against the relay, which Roost relies on for admission but never for confidentiality or authenticity.

## Alternatives

- Compare the relay's admission time with the prekey's replacement time: the device and the relay keep different clocks.
- Accept any first message for a kept signed prekey: anyone holding a leaked old prekey could forge first messages until it expired.
- Verify the relay's admission proof inside Roost: Roost would have to parse the relay's formats.
