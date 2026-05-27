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
