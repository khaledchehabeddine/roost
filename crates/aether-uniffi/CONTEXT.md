# UniFFI

The platform FFI binding layer that generates Swift and Kotlin bindings from Rust source so client platforms consume the Core API natively. It holds the storage abstraction trait the host app implements for keychain access.

## Language

**Binding Test Harness** (test-only binding surface):
Feature-gated Swift and Kotlin binding checks that exercise generated bindings through fixture replay and FFI-boundary regressions. It verifies generated binding behavior without becoming production SDK API.
Avoid: sample app, transport test, SDK feature

**SecureStorage** (one implementation per platform):
The generated UniFFI storage protocol the host app implements to expose its platform secret store
(iOS Keychain, Android Keystore) to Aether. Rust adapts that implementation into
`aether_core::SecureStorage` for Core; the implementation is provided at compile time.
Avoid: keychain, keystore, secrets store

**ProtocolStateStore** (one durable host transaction boundary):
The UniFFI trait or host-side adapter shape that loads and commits opaque Protocol State Blobs by
Protocol State Kind and key. Rust returns state updates and output values together; the host commits
those updates atomically with any outbox, event, or retry side effect it owns. Commit
implementations enforce each update's absent/digest/unchecked precondition to reject stale
concurrent writes.
Avoid: decoded protocol model, ratchet cache, SDK database

**Binding Surface** (generated API, not checked-in generated source):
The Rust `#[uniffi::export]` objects, records, enums, and foreign traits that generate Swift and
Kotlin APIs. Generated files live under `target/` during builds and tests; source review happens on
the Rust declarations and harnesses.
Avoid: handwritten FFI, SDK source drop, generated artifact

**Android AAR Distribution** (one generated Maven artifact):
The release-candidate Android package containing UniFFI-generated Kotlin classes and ABI-specific
`libaether.so` libraries under Maven coordinates. It is built from Rust source and generated
outputs during release verification; signing and pinned checksums are separate release steps.
Avoid: checked-in SDK, handwritten binding layer, final signed release artifact

**iOS Distribution Package** (one generated Swift Package per artifact version):
The release-candidate Swift Package assembled under `target/` from generated Swift sources and the
`Aether.xcframework` binary target. It is a packaging artifact, not checked-in SDK source.
Avoid: source package, signed release, pinned checksum publication

**Signed Release Artifact** (one final mobile binary artifact):
The release artifact generated from the tagged release commit and published with a detached
OpenPGP signature. For mobile releases this means the iOS xcframework archive and Android AAR, not
earlier release-candidate outputs or generated source directories.
Avoid: release-candidate artifact, reproducibility pass output, unsigned package

**Pinned Artifact Checksum** (one SHA-256 sidecar per signed artifact):
The release-published checksum generated after the final artifact bytes are fixed. Consumers verify
it together with the OpenPGP signature before their host build consumes the artifact.
Avoid: reproducibility manifest, CI scratch hash, trust root

## Example

**Dev:** Does Aether store private keys directly in the iOS Keychain?

**Domain expert:** Aether doesn't touch the Keychain. The host app implements the generated UniFFI
storage protocol against the Keychain and hands the implementation to Aether at compile time. The
FFI adapter translates that protocol into Core's `SecureStorage` trait, so Core sees a storage
contract, not the platform API.

**Dev:** So `InMemorySecureStorage` is the same shape, just with no platform behind it?

**Domain expert:** Right. It's a self-contained implementation used in tests, so nothing in Core or Crypto needs to know about platforms during testing.

**Dev:** Should Swift decode a ratchet blob to know which message number it is on?

**Domain expert:** No. Swift stores the blob opaquely and gives it back to Rust by Protocol State
Kind and key. Rust advances the protocol state and returns replacement blobs with the message or
event outputs that must be committed in the same host transaction. If another writer changed the
same blob first, Swift rejects the stale update using the digest precondition Rust returned.

## Flagged Ambiguities

None currently.
