# SecureStorage as Platform Abstraction

**Date:** 2026-03-29
**Status:** Accepted

## Decision

`SecureStorage` is a Rust trait with `store`, `load`, and `delete` methods that `KeyStore` consumes as a trait object. The host app provides platform implementations (iOS Keychain, Android Keystore) at construction time. An `InMemorySecureStorage` implementation ships in `hermes-core` for use in tests.

## Why

- Managers in `hermes-core` cannot call platform APIs directly — the crate is pure Rust with no iOS or Android dependencies
- A trait object lets the in-crate managers (`IdentityManager`, `SignedPreKeyManager`) share a single storage instance through `Arc<Mutex<Box<dyn _>>>` and erases the storage type at the FFI boundary; both are awkward with a generic parameter
- `InMemorySecureStorage` provides a self-contained test backend with no OS dependencies
- Keeping the trait in `hermes-core` rather than `hermes-uniffi` means the storage contract is defined at the layer that owns identity logic, not at the FFI boundary
