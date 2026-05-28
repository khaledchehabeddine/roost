# SecureStorage Platform Abstraction

**Status:** Accepted

`SecureStorage` is defined as a Rust trait in `aether-core` and consumed by `KeyStore` as a trait object, with the host app providing platform implementations (iOS Keychain, Android Keystore) at construction time. The trait lives in `aether-core` rather than at the FFI boundary because identity-key persistence is an identity-layer concern, and defining the contract at the layer that owns the concern keeps the FFI boundary clean and stable. Using a trait object lets the in-crate managers (`IdentityManager`, `SignedPreKeyManager`) share a single storage instance without their internal types leaking into the FFI signature, so the FFI surface stays stable as those managers evolve, and an `InMemorySecureStorage` implementation ships in the crate so the test suite exercises the storage contract without any OS dependency.
