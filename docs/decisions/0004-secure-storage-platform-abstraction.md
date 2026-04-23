# SecureStorage as Platform Abstraction

**Date:** 2026-03-29
**Status:** Accepted

## Decision

`SecureStorage` is a Rust trait with `store`, `load`, and `delete` methods that `IdentityManager` depends on via a
generic type parameter. The host app provides platform implementations (iOS Keychain, Android Keystore) at construction
time. An `InMemorySecureStorage` implementation ships in `hermes-core` for use in tests.

## Why

- `IdentityManager` cannot call platform APIs directly — `hermes-core` is pure Rust with no iOS or Android dependencies
- A generic type parameter (`IdentityManager<S: SecureStorage>`) lets the compiler monomorphize the correct backend
  with zero runtime overhead; no dynamic dispatch required
- `InMemorySecureStorage` provides a self-contained test backend with no OS dependencies
- Keeping the trait in `hermes-core` rather than `hermes-uniffi` means the storage contract is defined at the layer
  that owns identity logic, not at the FFI boundary
