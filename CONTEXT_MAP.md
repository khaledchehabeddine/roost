# Context Map

## Contexts

- [Core](crates/aether-core/CONTEXT.md) — high-level entity types and orchestration for Sessions, Identities, Devices, and Messages
- [Crypto](crates/aether-crypto/CONTEXT.md) — cryptographic primitives, key derivation, and protocol mechanics
- [UniFFI](crates/aether-uniffi/CONTEXT.md) — platform FFI bindings that expose the Core API to host apps

## Relationships

- **Crypto → Core**: Crypto provides primitives (AEAD, HKDF, Ratchet, X3DH) and the types they produce (key bundles, ratchet state). Core composes them into Session, Identity, Device, and Message lifecycle operations.
- **Core → UniFFI**: Core exports the high-level API and any host-implemented traits (e.g., `SecureStorage`). UniFFI surfaces them as platform bindings.
