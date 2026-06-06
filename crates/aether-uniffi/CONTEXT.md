# UniFFI

The platform FFI binding layer that generates Swift and Kotlin bindings from Rust source so client platforms consume the Core API natively. It holds the storage abstraction trait the host app implements for keychain access.

## Language

**Fixture Replay Harness** (test-only binding surface):
Feature-gated Swift and Kotlin binding checks that replay canonical Core and Crypto fixtures. It verifies generated binding behavior without becoming production SDK API.
Avoid: sample app, transport test, SDK feature

**SecureStorage** (one implementation per platform):
The Rust trait the host app implements to expose its platform secret store (iOS Keychain, Android Keystore) to Aether. Consumed as a trait object by `KeyStore` in Core; the implementation is provided at compile time.
Avoid: keychain, keystore, secrets store

## Example

**Dev:** Does Aether store private keys directly in the iOS Keychain?

**Domain expert:** Aether doesn't touch the Keychain. The host app implements `SecureStorage` against the Keychain and hands the implementation to Aether at compile time. Aether sees the trait, not the platform API. The trait itself lives in `aether-core` so the contract is defined at the layer that owns identity logic, not at the FFI boundary.

**Dev:** So `InMemorySecureStorage` is the same shape, just with no platform behind it?

**Domain expert:** Right. It's a self-contained implementation used in tests, so nothing in Core or Crypto needs to know about platforms during testing.

## Flagged Ambiguities

None currently.
