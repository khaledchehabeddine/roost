# Prekey Lifecycle

Prekeys live in SecureStorage under KeyStore, which already manages secret keys, and rotating the discovery key destroys all prekeys from earlier epochs. Signed prekeys rotate on a schedule the app triggers (ADR 0082), and KeyStore keeps a few old ones as long as the relay may hold a first message for them.

## Alternatives

- Keep only the last old signed prekey: first messages for several older prekeys can be waiting at once.
- Evict an unexpired signed prekey when space runs out: hitting a storage limit would make first messages undecryptable.
