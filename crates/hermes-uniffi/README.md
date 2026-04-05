# hermes-uniffi

UniFFI bindings. Exposes `IdentityManager`, `SecureStorage`, and `InMemorySecureStorage` to Kotlin (Android) and Swift (iOS) under the `hermes` namespace.

## Overview

This crate is the single API surface for Swift (iOS) and Kotlin (Android). It wraps `hermes-core` types into FFI-compatible types using Mozilla's [UniFFI](https://github.com/mozilla/uniffi-rs). `SecureStorage` is foreign-implementable so platform callers can inject their own storage implementations.

## Dependencies

- `hermes-core` — core domain logic
- [`uniffi`](https://github.com/mozilla/uniffi-rs) — generates Swift and Kotlin bindings from Rust
- `zeroize` — wraps FFI byte vectors in `Zeroizing` before passing to core

## Constraints

- Must only depend on `hermes-core`.
- Core types that aren't FFI-compatible are re-wrapped within this crate.

## Building for Android

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```sh
./scripts/build-android.sh
```

## Building for iOS

Requires Xcode command-line tools:

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
