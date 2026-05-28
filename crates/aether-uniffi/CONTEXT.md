# UniFFI

The platform FFI binding layer. Generates Swift and Kotlin bindings from Rust source so client platforms consume the Core API natively. Holds the storage abstraction trait the host app implements for keychain access.

## Language

{For each term: bold the name with optional cardinality in parentheses, write a one or two sentence definition of what it IS, list aliases to avoid.}

**SecureStorage** (one implementation per platform):
The Rust trait the host app implements to expose its platform secret store (iOS Keychain, Android Keystore) to Aether. Consumed as a trait object by `KeyStore` in Core; the implementation is provided at construction time.
Avoid: keychain, keystore, secrets store

## Example

{A short dialogue between a dev and a domain expert that uses the terms naturally and surfaces boundaries between related concepts.}

**Dev:** Does Aether store private keys directly in the iOS Keychain?

**Domain expert:** Aether doesn't touch the Keychain. The host app implements `SecureStorage` against the Keychain and hands the implementation to Aether at construction time. Aether sees the trait, not the platform API. The trait itself lives in `aether-core` so the contract is defined at the layer that owns identity logic, not at the FFI boundary.

**Dev:** So `InMemorySecureStorage` is the same shape, just with no platform behind it?

**Domain expert:** Right. It's a self-contained implementation used in tests, so nothing in Core or Crypto needs to know about platforms during testing.

## Flagged Ambiguities

{For each ambiguity: bold the conflicting term(s), state the conflict, give the resolution. Use "None currently." when empty.}

None currently.
