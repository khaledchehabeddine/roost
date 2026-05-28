# Context Map

## Contexts

{For each bounded context: link the display name to its CONTEXT.md path, follow with a one-line description of its responsibility.}

- [Core](./crates/aether-core/CONTEXT.md) — high-level entity types and orchestration for Sessions, Identities, Devices, and Messages
- [Crypto](./crates/aether-crypto/CONTEXT.md) — cryptographic primitives, key derivation, and protocol mechanics
- [UniFFI](./crates/aether-uniffi/CONTEXT.md) — platform FFI bindings and the storage abstraction trait

## Relationships

{For each relationship: bold the contexts with a directional arrow (→ one-way; ↔ shared types or bidirectional), follow with a one-line description of the integration.}

- **Crypto → Core**: Crypto provides primitives (AEAD, HKDF, Ratchet, X3DH-lite). Core composes them into Session and Identity lifecycle operations.
- **Core → UniFFI**: Core exports the high-level API. UniFFI wraps it for platform consumption and defines the `SecureStorage` trait the host app implements.
- **Crypto ↔ Core**: Shared types for `SessionID`, `IdentityKey`, and `MessageID`.
