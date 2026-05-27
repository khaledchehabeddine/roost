# SecureStorage as Platform Abstraction

**Date:** 2026-03-29
**Status:** Accepted

## Decision

`SecureStorage` is a Rust trait with methods that `KeyStore` consumes as a trait object. The client app provides platform implementations at construction time. An `InMemorySecureStorage` implementation is added for testing.

## Why

- Managers in `aether-core` cannot call platform APIs directly
- A trait object lets the in-crate managers (`IdentityManager`, `SignedPreKeyManager`) share a single storage instance and erases the storage type at the FFI boundary
- `InMemorySecureStorage` provides a self-contained test backend with no OS dependencies
- Keeping the trait in `aether-core` rather than `aether-uniffi` means the storage contract is defined at the layer that owns identity logic, not at the FFI boundary
