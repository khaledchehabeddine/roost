#!/usr/bin/env bash
# Build a universal xcframework for iOS device and iOS Simulator.
# Requires Xcode command-line tools and the iOS Rust targets.
#
# Usage:
#   ./scripts/build-xcframework.sh
set -euo pipefail

CRATE="hermes-uniffi"
LIB="libhermes_uniffi"
OUT="target/xcframework"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim

cargo build --release --target aarch64-apple-ios        -p "$CRATE"
cargo build --release --target aarch64-apple-ios-sim    -p "$CRATE"

mkdir -p "$OUT/swift"

cargo run --bin uniffi-bindgen -- generate \
    --library "target/aarch64-apple-ios/release/${LIB}.a" \
    --language swift \
    --out-dir "$OUT/swift"

xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/release/${LIB}.a" \
    -headers "$OUT/swift" \
    -library "target/aarch64-apple-ios-sim/release/${LIB}.a" \
    -headers "$OUT/swift" \
    -output "$OUT/Hermes.xcframework"

echo "xcframework written to $OUT/Hermes.xcframework"
echo "Swift bindings written to $OUT/swift/"
