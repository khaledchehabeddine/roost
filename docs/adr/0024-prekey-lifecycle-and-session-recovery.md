# Prekey Lifecycle and Session Recovery

Prekeys live in SecureStorage under KeyStore, which already manages secret keys, rotating the Discovery Key destroys all prekeys from earlier Epochs, and a Session is never repaired, so recovery replaces one only with a new X3DH exchange from a fresh prekey bundle (ADR 0050). Signed prekeys rotate on a schedule, and KeyStore keeps a few old ones as long as the Relay may hold a first Message, but uses one only after the app proves the Relay admitted that exact first Message against it, since the Relay admits only first Messages that name its current signed prekey. The proof guards what the app passes to Roost, not against the Relay itself, because Roost relies on the Relay for admission and availability but never for confidentiality or authenticity.

## Alternatives

- Rotate signed prekeys while publishing: publishing should only read, so the app controls when new bundles appear.
- Keep only the last old signed prekey: first messages for several older prekeys can be waiting at once.
- Evict an unexpired signed prekey when space runs out: hitting a storage limit would make first messages undecryptable.
- Replenish one-time prekeys while receiving: publishing is the app's call, and receiving should only use up the prekey the Message names.
- Compare the Relay's admission time with the time a signed prekey was replaced: the Device and the Relay keep different clocks, and the Relay learns of a rotation only when the new prekey is uploaded.
- Accept any first Message for a kept signed prekey: anyone holding a leaked old prekey could forge first Messages until it expired.
- Verify the Relay's admission proof inside Roost: Roost would have to parse the Relay's formats.
