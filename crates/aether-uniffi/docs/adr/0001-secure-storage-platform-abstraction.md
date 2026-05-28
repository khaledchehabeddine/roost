# SecureStorage as Platform Abstraction

**Status:** Accepted

`SecureStorage` is a Rust trait that `KeyStore` consumes as a trait object, with the host app providing platform implementations at construction time and an `InMemorySecureStorage` available as a self-contained test backend. The trait lives in `aether-core` so the storage contract is defined at the layer that owns identity logic rather than at the FFI boundary; the trait object lets the in-crate managers (`IdentityManager`, `SignedPreKeyManager`) share a single storage instance and erases the storage type at the FFI boundary.
