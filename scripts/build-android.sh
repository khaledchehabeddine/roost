#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"

rm -rf target/android
rustup target add aarch64-linux-android
cargo ndk -t arm64-v8a -o target/android/jniLibs build --locked --release -p roost-client
cargo run --locked --bin uniffi-bindgen -- generate \
    target/aarch64-linux-android/release/libroost_client.so \
    --language kotlin --no-format --out-dir target/android/kotlin
cargo run --locked --bin convert-docs -- kotlin \
    target/android/kotlin/com/chirp/roost/roost_client.kt
gradle -p android publishReleasePublicationToLocalRepository
