#!/usr/bin/env bash
#
# Build an xcframework for iOS devices and simulators.

set -euo pipefail

CRATE="hermes-uniffi"
LIB="libhermes"
OUT="target/xcframework"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim

cargo build --release --target aarch64-apple-ios -p "$CRATE"
cargo build --release --target aarch64-apple-ios-sim -p "$CRATE"

mkdir -p "$OUT/Headers" "$OUT/Modules" "$OUT/Sources"

# Generate Swift bindings using the dedicated uniffi-bindgen-swift binary.
cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Headers" --headers

cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Modules" --modulemap --xcframework --modulemap-filename module.modulemap

cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Sources" --swift-sources

xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/release/${LIB}.a" \
    -headers "$OUT/Headers" \
    -library "target/aarch64-apple-ios-sim/release/${LIB}.a" \
    -headers "$OUT/Headers" \
    -output "$OUT/Hermes.xcframework"

echo "xcframework written to $OUT/Hermes.xcframework"
echo "Swift sources written to $OUT/Sources/"
