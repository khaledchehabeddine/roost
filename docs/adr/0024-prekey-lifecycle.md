# Prekey Lifecycle

Prekeys live in SecureStorage under KeyStore, which already manages secret keys, and rotating the Discovery Key destroys all prekeys from earlier Epochs. Signed prekeys rotate on a schedule, and KeyStore keeps a few old ones as long as the Relay may hold a first Message for them.

## Alternatives

- Rotate signed prekeys while publishing: publishing should only read, so the app controls when new bundles appear.
- Keep only the last old signed prekey: first Messages for several older prekeys can be waiting at once.
- Evict an unexpired signed prekey when space runs out: hitting a storage limit would make first Messages undecryptable.
- Replenish one-time prekeys while receiving: publishing is the app's call, and receiving should only use up the prekey the Message names.
