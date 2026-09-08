#!/usr/bin/env bash
# Compile the generated Swift API and Rust library into the Roost binary distribution.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OUT="$ROOT/target/xcframework"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
MIN_IOS="${ROOST_IOS_DEPLOYMENT_TARGET:-13.0}"
cd "$ROOT"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    if [[ ! -d "$(rustc --print sysroot)/lib/rustlib/$target/lib" ]]; then
        rustup target add "$target"
    fi
    IPHONEOS_DEPLOYMENT_TARGET="$MIN_IOS" cargo build --locked --release --target "$target" -p roost-client
done

rm -rf "$OUT"
mkdir -p "$OUT/generated"
cargo run --locked --bin uniffi-bindgen-swift -- \
    target/aarch64-apple-ios/release/libroost_client.a "$OUT/generated" --swift-sources --headers

build_framework() {
    local rust_target="$1" swift_target="$2" sdk_name="$3" identifier="$4"
    local framework="$OUT/$identifier/Roost.framework"
    local modules="$framework/Modules/Roost.swiftmodule"
    local sdk module_target
    sdk="$(xcrun --sdk "$sdk_name" --show-sdk-path)"
    module_target="${swift_target/$MIN_IOS/}"
    mkdir -p "$framework/Headers" "$modules"
    cp "$OUT/generated/RoostFFI.h" "$framework/Headers/"
    cat > "$framework/Modules/module.modulemap" <<'MODULE'
framework module Roost {
    umbrella header "RoostFFI.h"
    export *
    module * { export * }
}
MODULE
    cat > "$framework/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.github.relaynet.roost</string>
<key>CFBundleName</key><string>Roost</string>
<key>CFBundleExecutable</key><string>Roost</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>MinimumOSVersion</key><string>$MIN_IOS</string>
</dict></plist>
PLIST
    xcrun --sdk "$sdk_name" swiftc "$OUT/generated/Roost.swift" \
        -target "$swift_target" -sdk "$sdk" -parse-as-library \
        -module-name Roost -swift-version 5 -enable-library-evolution -import-underlying-module \
        -F "$OUT/$identifier" -module-cache-path "$OUT/module-cache" \
        -emit-library -emit-module \
        -emit-module-path "$modules/$module_target.swiftmodule" \
        -emit-module-interface-path "$modules/$module_target.swiftinterface" \
        -Xlinker -force_load -Xlinker "$ROOT/target/$rust_target/release/libroost_client.a" \
        -Xlinker -install_name -Xlinker "@rpath/Roost.framework/Roost" \
        -o "$framework/Roost"
}

build_framework aarch64-apple-ios "arm64-apple-ios$MIN_IOS" iphoneos ios-arm64
build_framework aarch64-apple-ios-sim "arm64-apple-ios$MIN_IOS-simulator" iphonesimulator sim-arm64
build_framework x86_64-apple-ios "x86_64-apple-ios$MIN_IOS-simulator" iphonesimulator sim-x86_64

mkdir -p "$OUT/ios-arm64_x86_64-simulator"
cp -R "$OUT/sim-arm64/Roost.framework" "$OUT/ios-arm64_x86_64-simulator/"
cp "$OUT/sim-x86_64/Roost.framework/Modules/Roost.swiftmodule/"* \
    "$OUT/ios-arm64_x86_64-simulator/Roost.framework/Modules/Roost.swiftmodule/"
lipo -create "$OUT/sim-arm64/Roost.framework/Roost" "$OUT/sim-x86_64/Roost.framework/Roost" \
    -output "$OUT/ios-arm64_x86_64-simulator/Roost.framework/Roost"
xcodebuild -create-xcframework \
    -framework "$OUT/ios-arm64/Roost.framework" \
    -framework "$OUT/ios-arm64_x86_64-simulator/Roost.framework" \
    -output "$OUT/Roost.xcframework"
