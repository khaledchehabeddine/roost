# Postcard Message Wire Format

**Status:** Accepted

Messages cross the public Rust API as Core-owned structs encoded with Postcard, including a library-controlled version byte inside the encoded Message rather than in a consumer transport envelope. Core owns the type because Messages are Session-level entities, while the encoded bytes remain opaque to transports; a crate-owned `MessageId` newtype and explicit payload-kind tags keep the public surface stable without exposing a UUID dependency or relying on enum layout. The v1 `text` kind identifies encrypted application text bytes, not plaintext user content.

## Considered Options

- Put the codec in `aether-crypto`. Rejected because the encoded Message is an application-level packet around ciphertext and protocol payload bytes, not a primitive.
- Use `uuid::Uuid` in the public API. Rejected because only the 16-byte UUID shape is required at this boundary, and a crate-owned newtype is easier to preserve across Rust and future FFI surfaces.
