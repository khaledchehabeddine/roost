# aether-core

Storage-backed key management for private messaging clients.

## Scope

- Owns the local identity lifecycle, encrypted backup import/export, discovery-key rotation, signed-pre-key rotation, and one-time-pre-key pool management.
- Uses the two-key identity model: the long-lived Ed25519 identity key signs the discovery-key bundle; the discovery key signs signed pre-keys.
- Publishes `PublicationBundle` as the verified discovery-key plus signed-pre-key pair. One-time pre-key bundles come from `KeyStore::replenish_one_time_prekeys`.
- Delegates protocol crypto to `aether-crypto`; this crate adds persistence and lifecycle coordination.

## Notes

- `KeyStore` serializes multi-key updates across cloned handles.
- Platform code supplies `SecureStorage`; `InMemorySecureStorage` is for tests and examples.
