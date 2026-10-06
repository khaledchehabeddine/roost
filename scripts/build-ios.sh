#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT="$ROOT/target/ios"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
ZIP="$OUT/Roost-v$VERSION.xcframework.zip"
# Keep in step with .iOS(.v13) in the Package.swift that release.yml writes.
MIN_IOS=13.0
cd "$ROOT"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim
IPHONEOS_DEPLOYMENT_TARGET="$MIN_IOS" cargo build --locked --release -p roost-client \
    --target aarch64-apple-ios --target aarch64-apple-ios-sim

rm -rf "$OUT"
mkdir -p "$OUT/generated"
cargo run --locked --bin uniffi-bindgen -- generate \
    target/aarch64-apple-ios/release/libroost_client.a --language swift --no-format --out-dir "$OUT/generated"
cargo run --locked --bin convert-docs -- swift "$OUT/generated/Roost.swift"

build_framework() {
    local rust_target="$1" swift_target="$2" sdk_name="$3" identifier="$4"
    local framework="$OUT/$identifier/Roost.framework"
    local modules="$framework/Modules/Roost.swiftmodule"
    local module_target="${swift_target/$MIN_IOS/}"
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
<key>CFBundleIdentifier</key><string>com.chirp.roost</string>
<key>CFBundleName</key><string>Roost</string>
<key>CFBundleExecutable</key><string>Roost</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>MinimumOSVersion</key><string>$MIN_IOS</string>
</dict></plist>
PLIST
    xcrun --sdk "$sdk_name" swiftc "$OUT/generated/Roost.swift" \
        -O -target "$swift_target" -parse-as-library \
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
build_framework aarch64-apple-ios-sim "arm64-apple-ios$MIN_IOS-simulator" iphonesimulator ios-arm64-simulator

xcodebuild -create-xcframework \
    -framework "$OUT/ios-arm64/Roost.framework" \
    -framework "$OUT/ios-arm64-simulator/Roost.framework" \
    -output "$OUT/Roost.xcframework"
(cd "$OUT" && zip -qry "$ZIP" Roost.xcframework)
printf 'XCFramework archive: %s\n' "$ZIP"
