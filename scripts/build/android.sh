#!/usr/bin/env bash
#
# Build .so libraries and Kotlin bindings for Android.

set -euo pipefail

CRATE="aether-uniffi"
LIB="libaether"
OUT="target/android"

TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "x86_64-linux-android"
)

rustup target add "${TARGETS[@]}"

for TARGET in "${TARGETS[@]}"; do
    cargo ndk --target "$TARGET" build --release -p "$CRATE"
done

mkdir -p "$OUT/kotlin"

cargo run --bin uniffi-bindgen -- generate \
    "target/aarch64-linux-android/release/${LIB}.so" \
    --language kotlin \
    --out-dir "$OUT/kotlin"

for TARGET in "${TARGETS[@]}"; do
    echo ".so written to target/$TARGET/release/${LIB}.so"
done
echo "Kotlin bindings written to $OUT/kotlin/"
