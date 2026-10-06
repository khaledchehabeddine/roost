#!/usr/bin/env bash
# Build the Rust library and its generated Kotlin API into a local Maven AAR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT="$ROOT/target/android"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
cd "$ROOT"

rm -rf "$OUT"
rustup target add aarch64-linux-android x86_64-linux-android
cargo ndk -t arm64-v8a -t x86_64 -o "$OUT/jniLibs" build --locked --release -p roost-client
cargo run --locked --bin uniffi-bindgen -- generate \
    target/aarch64-linux-android/release/libroost_client.so --language kotlin --no-format --out-dir "$OUT/kotlin"
cargo run --locked --bin convert-docs -- kotlin "$OUT/kotlin/com/chirp/roost/roost_client.kt"
gradle --no-daemon -p android -ProostVersion="$VERSION" publishReleasePublicationToLocalRepository
printf 'Android Maven package: %s\n' "$OUT/maven/com/chirp/roost/$VERSION/roost-$VERSION.aar"
