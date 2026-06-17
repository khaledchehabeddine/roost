# Building Mobile

## Android

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```bash
./scripts/build/android.sh
```

## iOS

Requires Xcode command-line tools:

```bash
./scripts/build/xcframework.sh
```

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
