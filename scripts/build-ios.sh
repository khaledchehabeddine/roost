#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

MIN_IOS=15.0

rm -rf target/ios
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET="$MIN_IOS" cargo build --locked --release -p roost-client \
    --target aarch64-apple-ios --target aarch64-apple-ios-sim
cargo run --locked --bin uniffi-bindgen -- generate \
    target/aarch64-apple-ios/release/libroost_client.a \
    --language swift --no-format --out-dir target/ios/generated
cargo run --locked --bin convert-docs -- swift target/ios/generated/Roost.swift
mkdir -p target/ios/headers
cp target/ios/generated/RoostFFI.h target/ios/headers/
cp target/ios/generated/RoostFFI.modulemap target/ios/headers/module.modulemap
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libroost_client.a -headers target/ios/headers \
    -library target/aarch64-apple-ios-sim/release/libroost_client.a -headers target/ios/headers \
    -output target/ios/RoostFFI.xcframework
(cd target/ios && zip -qr RoostFFI.xcframework.zip RoostFFI.xcframework)

# Nothing else compiles the Swift bindings before an app does.
sed 's|url: "{URL}",|path: "RoostFFI.xcframework.zip"|; /checksum:/d' \
    ios/Package.swift > target/ios/Package.swift
mkdir -p target/ios/Sources/Roost
cp target/ios/generated/Roost.swift target/ios/Sources/Roost/
(cd target/ios && xcodebuild build -quiet -scheme Roost \
    -destination 'generic/platform=iOS' -derivedDataPath DerivedData)
