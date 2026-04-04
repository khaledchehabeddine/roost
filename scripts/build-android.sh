#!/usr/bin/env bash
# Build .so libraries for Android ABIs and generate Kotlin bindings.
set -euo pipefail

CRATE="hermes-uniffi"
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
    "target/aarch64-linux-android/release/libhermes.so" \
    --language kotlin \
    --out-dir "$OUT/kotlin"

echo ".so files written to target/<abi>/release/"
echo "Kotlin bindings written to $OUT/kotlin/"
