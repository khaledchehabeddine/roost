# aether-crypto

Protocol crypto for private end-to-end encrypted messaging.

## Scope

- Provides identity, discovery-key, signed-pre-key, one-time-pre-key, X3DH, and Double Ratchet primitives for Rust callers.
- Uses a two-key identity model: the identity verifying key authenticates the discovery key; the discovery key authenticates signed pre-keys.
- Accepts publication material as `DiscoveryKeyBundle`, `SignedPreKeyBundle`, and optional `OneTimePreKeyBundle`, then establishes sessions with `initiate` and `accept`.
- Serializes handshake transport with `HandshakeEnvelope::to_bytes` and `HandshakeEnvelope::from_bytes`.

## Notes

- Replay tracking, pre-key expiration policy, and transport framing belong above this crate.
- Full X3DH session establishment is Rust API only in this release.
