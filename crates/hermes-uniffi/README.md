# hermes-uniffi

UniFFI bindings. Exposes `IdentityManager`, `SecureStorage`, and `InMemorySecureStorage` to Kotlin (Android) and Swift (iOS) under the `hermes` namespace.

## Constraints

- May only depend on `hermes-core`.
- Core types are wrapped in FFI-compatible types within this crate.

## Building for Android

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```sh
./scripts/build-android.sh
```

## Building for iOS

Requires Xcode command-line tools and the iOS Rust targets:

```sh
./scripts/build-xcframework.sh
```

## Generating Bindings Manually

```sh
cargo build -p hermes-uniffi

# Kotlin
cargo run --bin uniffi-bindgen -- generate \
    target/debug/libhermes.dylib \
    --language kotlin \
    --out-dir target/bindings/kotlin

# Swift (headers + sources)
cargo run --bin uniffi-bindgen-swift -- \
    target/debug/libhermes.dylib \
    target/bindings/swift \
    --swift-sources --headers
```

> [!NOTE]
> On Linux replace `.dylib` with `.so`.
