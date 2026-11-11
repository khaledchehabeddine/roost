# Relay Admission Proofs

Roost opens a first message for a replaced signed prekey only after the app proves the relay admitted that exact message against it, which the relay does only while the prekey is current. The proof checks what the app passes, not the relay, which Roost trusts for admission but never for confidentiality or authenticity.

## Alternatives

- Compare the admission time with the prekey's replacement time: the device and the relay keep different clocks.
- Accept any first message for a kept signed prekey: anyone holding a leaked old prekey could forge first messages until it expired.
- Verify the relay's proof inside Roost: Roost would have to parse the relay's formats.
