# hermes-uniffi

UniFFI bindings crate. Exposes `IdentityManager`, `SecureStorage`, and `InMemorySecureStorage` to Swift (iOS) and Kotlin (Android) under the `hermes` namespace.

## Constraints

- May only depend on `hermes-core`.
- Core types are wrapped in FFI-compatible types within this crate.

## Building for iOS (xcframework)

Requires Xcode command-line tools and the iOS Rust targets:

```sh
./scripts/build-xcframework.sh
```

The xcframework is written to `target/xcframework/Hermes.xcframework`. Swift sources are generated in `target/xcframework/Sources/`.

## Building for Android (.so)

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```sh
NDK_HOME=/path/to/ndk ./scripts/build-android.sh
```

`.so` files for `aarch64`, `armv7`, and `x86_64` are written to `target/<abi>/release/`. Kotlin bindings are generated in `target/android/kotlin/`.

## Generating bindings manually

```sh
cargo build -p hermes-uniffi

# Swift (headers + sources)
cargo run --bin uniffi-bindgen-swift -- \
    target/debug/libhermes.dylib \
    target/bindings/swift \
    --swift-sources --headers

# Kotlin
cargo run --bin uniffi-bindgen -- generate \
    target/debug/libhermes.dylib \
    --language kotlin \
    --out-dir target/bindings/kotlin
```

On Linux replace `.dylib` with `.so`.
