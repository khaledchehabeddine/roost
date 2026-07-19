#!/usr/bin/env bash
#
# Build .so libraries and Kotlin bindings for Android.

set -euo pipefail

CRATE="aether-uniffi"
LIB="libaether"
OUT="target/android"
FEATURES="${AETHER_CARGO_FEATURES:-}"

FEATURE_ARGS=()
if [[ -n "$FEATURES" ]]; then
    FEATURE_ARGS=(--features "$FEATURES")
fi

TARGETS=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "x86_64-linux-android:x86_64"
)

RUST_TARGETS=()
for TARGET_PAIR in "${TARGETS[@]}"; do
    RUST_TARGETS+=("${TARGET_PAIR%%:*}")
done

rustup target add "${RUST_TARGETS[@]}"

for TARGET_PAIR in "${TARGETS[@]}"; do
    TARGET="${TARGET_PAIR%%:*}"
    cargo ndk --target "$TARGET" build --release -p "$CRATE" "${FEATURE_ARGS[@]}"
done

rm -rf "$OUT/kotlin" "$OUT/jniLibs"
mkdir -p "$OUT/kotlin" "$OUT/jniLibs"

cargo run -p "$CRATE" --bin uniffi-bindgen "${FEATURE_ARGS[@]}" -- generate \
    "target/aarch64-linux-android/release/${LIB}.so" \
    --language kotlin \
    --out-dir "$OUT/kotlin"

for TARGET_PAIR in "${TARGETS[@]}"; do
    TARGET="${TARGET_PAIR%%:*}"
    ABI="${TARGET_PAIR##*:}"
    mkdir -p "$OUT/jniLibs/$ABI"
    cp "target/$TARGET/release/${LIB}.so" "$OUT/jniLibs/$ABI/${LIB}.so"
    echo ".so written to target/$TARGET/release/${LIB}.so"
    echo ".so staged to $OUT/jniLibs/$ABI/${LIB}.so"
done
echo "Kotlin bindings written to $OUT/kotlin/"
