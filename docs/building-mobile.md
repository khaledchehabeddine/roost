# Building Mobile

## Android

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```bash
./scripts/build/android.sh
```

This writes ABI-specific shared libraries to `target/android/jniLibs/` and generated Kotlin
bindings to `target/android/kotlin/`.

Build the Android AAR and publish it to a local Maven repository:

```bash
scripts/release/android-aar.sh
```

The local artifact is published as:

```text
com.aurelion:aether:<workspace-version>
```

by default under `target/android/maven/`. Override the version or local repository with
`AETHER_ANDROID_VERSION` and `AETHER_ANDROID_MAVEN_REPO`.

Verify a consumer against that local repository with:

```bash
scripts/test/android-aar-consumer.sh
```

The consumer check resolves the Maven artifact and runs the Kotlin binding coverage flow on an
Android API 36 managed device. Release consumers must verify the final AAR signature and pinned
checksum before Gradle consumes the artifact:

```bash
scripts/release/verify-artifact.sh \
  aether-0.9.0.aar \
  aether-0.9.0.aar.asc \
  aether-0.9.0.aar.sha256 \
  aether-v0.9.0-release-key.asc
```

Run this as a build preflight with `AETHER_RELEASE_GPG_FINGERPRINT` set to the expected release key
fingerprint. Verification fails closed when the fingerprint is missing or mismatched; do not fall
back to an unsigned, checksum-mismatched, or wrong-key-signed artifact.

## iOS

Requires Xcode command-line tools:

```bash
./scripts/build/xcframework.sh
```

To assemble the generated Swift Package binary distribution:

```bash
./scripts/build/ios-package.sh
```

The package is written under `target/ios-distribution/aether-ios-v<version>/` with product
`Aether`, generated Swift source target `Aether`, and binary target `AetherFFI`.

Verify the package with an iOS Simulator consumer:

```bash
scripts/test/ios-package-consumer.sh target/ios-distribution/aether-ios-v0.9.0
```

Release consumers must verify the final xcframework archive signature and pinned checksum before
the Swift Package consumes the binary target:

```bash
scripts/release/verify-artifact.sh \
  Aether-v0.9.0.xcframework.zip \
  Aether-v0.9.0.xcframework.zip.asc \
  Aether-v0.9.0.xcframework.zip.sha256 \
  aether-v0.9.0-release-key.asc
```

Run this as a build preflight with `AETHER_RELEASE_GPG_FINGERPRINT` set to the expected release key
fingerprint. Verification fails closed when the fingerprint is missing or mismatched; do not fall
back to an unsigned, checksum-mismatched, or wrong-key-signed artifact.

## Manual Bindings

```bash
cargo build -p aether-uniffi

# Kotlin
cargo run --bin uniffi-bindgen -- generate \
    target/debug/libaether.dylib \
    --language kotlin \
    --out-dir target/bindings/kotlin

# Swift (headers + sources)
cargo run --bin uniffi-bindgen-swift -- \
    target/debug/libaether.dylib \
    target/bindings/swift \
    --swift-sources --headers
```

> [!NOTE]                                                                                                                                                  
> On Linux, replace `.dylib` with `.so`.

Generated Swift and Kotlin sources are build outputs. Keep them under `target/` or your app build
cache; do not commit them to this repository.

## iOS Artifact Verification

Release-candidate CI uploads `Aether-v0.9.0.xcframework.zip`, the local Swift Package, and
`SHA256SUMS` from the same build. Release-tag CI publishes the final OpenPGP signature, pinned
checksum, and public release key for the xcframework archive. Treat release-candidate hashes as
reproducibility evidence, not as the distribution trust root.

## Binding Surface

- Implement `SecureStorage` in the host app and pass it to `KeyStore`.
- Implement or adapt `ProtocolStateStore` in the host app for opaque `ProtocolStateKind + key`
  blobs.
- Commit returned `ProtocolStateUpdate` values atomically with the message, acknowledgment, event,
  retry, or outbox side effect returned from the same call.
- Reject stale commits by enforcing each update's commit check: absent for new blobs, digest match
  for snapshot-derived replacements/deletes, unchecked only for wipe updates.
- Use `KeyStore` for identity, prekeys, backup, session establishment, message encryption,
  message decryption, and acknowledgment processing.
- Use `ProtocolStateEngine` for protocol-state initialization/wipe, contacts/trust/blocking,
  pending acknowledgments, retry instructions, hardening limits, and snapshot loading.
