#!/usr/bin/env bash
#
# Build the iOS xcframework and assemble a local Swift Package distribution.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PKGID="$(cargo pkgid --manifest-path "$ROOT/crates/aether-uniffi/Cargo.toml")"
VERSION="${PKGID##*#}"
DIST="$ROOT/target/ios-distribution"
PACKAGE="$DIST/aether-ios-v$VERSION"
ZIP="$DIST/Aether-v$VERSION.xcframework.zip"
PACKAGE_ZIP="$DIST/Aether-v$VERSION.swift-package.zip"

cd "$ROOT"

scripts/build/xcframework.sh

rm -rf "$PACKAGE" "$ZIP" "$PACKAGE_ZIP"
mkdir -p "$PACKAGE/Artifacts" "$PACKAGE/Sources/Aether"

cp -R "$ROOT/target/xcframework/Aether.xcframework" "$PACKAGE/Artifacts/Aether.xcframework"
cp "$ROOT"/target/xcframework/Sources/*.swift "$PACKAGE/Sources/Aether/"

cat > "$PACKAGE/Package.swift" <<'PACKAGE'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AetherIOS",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "Aether", targets: ["Aether"]),
    ],
    targets: [
        .target(
            name: "Aether",
            dependencies: ["AetherFFI"],
            path: "Sources/Aether"
        ),
        .binaryTarget(
            name: "AetherFFI",
            path: "Artifacts/Aether.xcframework"
        ),
    ]
)
PACKAGE

timestamp="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
stamp="$(date -u -r "$timestamp" +%Y%m%d%H%M.%S)"
find "$PACKAGE" -exec touch -h -t "$stamp" {} +

(
    cd "$PACKAGE/Artifacts"
    find Aether.xcframework -type f | LC_ALL=C sort | zip -X -q "$ZIP" -@
)

(
    cd "$DIST"
    find "aether-ios-v$VERSION" -type f | LC_ALL=C sort | zip -X -q "$PACKAGE_ZIP" -@
)

echo "iOS package written to $PACKAGE"
echo "xcframework archive written to $ZIP"
echo "Swift Package archive written to $PACKAGE_ZIP"
