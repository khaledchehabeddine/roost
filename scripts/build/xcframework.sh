#!/usr/bin/env bash
#
# Build an xcframework and Swift bindings for iOS.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CRATE="aether-uniffi"
LIB="libaether"
OUT="$ROOT/target/xcframework"
SYSROOT="$(rustc --print sysroot)"
IOS_DEPLOYMENT_TARGET="${AETHER_IOS_DEPLOYMENT_TARGET:-13.0}"

cd "$ROOT"

ensure_rust_target() {
    local target="$1"

    if rustup target list --installed | grep -Fxq "$target"; then
        return
    fi
    if [[ -d "$SYSROOT/lib/rustlib/$target/lib" ]]; then
        return
    fi
    rustup target add "$target"
}

build_staticlib() {
    local target="$1"
    local min_version_flag="$2"

    CFLAGS="${CFLAGS:-} $min_version_flag" \
        IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" \
        cargo build --release --target "$target" -p "$CRATE"
}

write_xcframework_info_plist() {
    cat > "$OUT/Aether.xcframework/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>BinaryPath</key>
			<string>${LIB}.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>${LIB}.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>BinaryPath</key>
			<string>${LIB}.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64_x86_64-simulator</string>
			<key>LibraryPath</key>
			<string>${LIB}.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
				<string>x86_64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLIST
}

ensure_rust_target aarch64-apple-ios
ensure_rust_target aarch64-apple-ios-sim
ensure_rust_target x86_64-apple-ios

build_staticlib aarch64-apple-ios "-miphoneos-version-min=$IOS_DEPLOYMENT_TARGET"
build_staticlib aarch64-apple-ios-sim "-mios-simulator-version-min=$IOS_DEPLOYMENT_TARGET"
build_staticlib x86_64-apple-ios "-mios-simulator-version-min=$IOS_DEPLOYMENT_TARGET"

rm -rf "$OUT"
mkdir -p "$OUT/Headers" "$OUT/Libraries/ios-simulator" "$OUT/Sources"

cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Headers" --headers

cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Headers" --modulemap --module-name AetherFFI --modulemap-filename module.modulemap

cargo run --bin uniffi-bindgen-swift -- \
    "target/aarch64-apple-ios/release/${LIB}.a" \
    "$OUT/Sources" --swift-sources

lipo -create \
    "target/aarch64-apple-ios-sim/release/${LIB}.a" \
    "target/x86_64-apple-ios/release/${LIB}.a" \
    -output "$OUT/Libraries/ios-simulator/${LIB}.a"

xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/release/${LIB}.a" \
    -headers "$OUT/Headers" \
    -library "$OUT/Libraries/ios-simulator/${LIB}.a" \
    -headers "$OUT/Headers" \
    -output "$OUT/Aether.xcframework"
write_xcframework_info_plist

echo "xcframework written to $OUT/Aether.xcframework"
echo "Swift sources written to $OUT/Sources/"
