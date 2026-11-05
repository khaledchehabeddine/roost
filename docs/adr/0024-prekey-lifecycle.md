# Prekey Lifecycle

Prekeys live in SecureStorage under KeyStore, which already manages secret keys, and rotating the Discovery Key destroys all prekeys from earlier Epochs. Signed prekeys rotate on a schedule the app triggers (ADR 0092), and KeyStore keeps a few old ones as long as the Relay may hold a First Message for them.

## Alternatives

- Keep only the last old signed prekey: First Messages for several older prekeys can be waiting at once.
- Evict an unexpired signed prekey when space runs out: hitting a storage limit would make First Messages undecryptable.
