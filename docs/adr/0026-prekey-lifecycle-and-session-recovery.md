# Prekey Lifecycle and Session Recovery

Prekeys live in SecureStorage under KeyStore, which already manages secret keys, and rotating the Discovery Key destroys all prekeys from earlier Epochs. Signed prekeys rotate on a schedule, and KeyStore keeps a few old ones for a while so first messages sent just before a rotation still decrypt. A Dead Session is never repaired, and only a new X3DH exchange with a fresh prekey bundle replaces it.

## Alternatives

- Rotate signed prekeys while publishing: publishing should only read, so the app controls when new bundles appear.
- Keep only the last old signed prekey: first messages for several older prekeys can be waiting at once.
- Evict an unexpired signed prekey when space runs out: hitting a storage limit would make first messages undecryptable.
- Replenish one-time prekeys while receiving: publishing is the app's call, and receiving should only use up the prekey the Message names.
