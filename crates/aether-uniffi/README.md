# aether-uniffi

UniFFI bindings for storage-backed key management.

## Scope

- Exposes FFI-safe `KeyStore`, `SecureStorage`, identity records, and publication records for SDK clients.
- Preserves the two-key publication model through `PublicationBundle`: discovery-key bundle plus signed-pre-key bundle.
- Converts internal errors into client-relevant `AetherError` variants.

## Notes

- Secret bytes are wrapped inside the adapter layer as soon as they cross into Rust.
- X3DH session establishment and one-time pre-key publication remain Rust-only for this release.
