#!/usr/bin/env bash
#
# Build the iOS xcframework and assemble a local Swift Package distribution.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PKGID="$(cargo pkgid --manifest-path "$ROOT/crates/roost-client/Cargo.toml")"
VERSION="${PKGID##*#}"
DIST="$ROOT/target/ios-distribution"
PACKAGE="$DIST/roost-swift-v$VERSION"
ZIP="$DIST/Roost-v$VERSION.xcframework.zip"
PACKAGE_ZIP="$DIST/Roost-v$VERSION.swift-package.zip"

cd "$ROOT"

scripts/build/xcframework.sh

rm -rf "$PACKAGE" "$ZIP" "$PACKAGE_ZIP"
mkdir -p "$PACKAGE/Artifacts"

cp -R "$ROOT/target/xcframework/Roost.xcframework" "$PACKAGE/Artifacts/Roost.xcframework"

cat > "$PACKAGE/Package.swift" <<'PACKAGE'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Roost",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "Roost", targets: ["Roost"]),
    ],
    targets: [
        .binaryTarget(
            name: "Roost",
            path: "Artifacts/Roost.xcframework"
        ),
    ]
)
PACKAGE

timestamp="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
stamp="$(date -u -r "$timestamp" +%Y%m%d%H%M.%S)"
find "$PACKAGE" -exec touch -h -t "$stamp" {} +

(
    cd "$PACKAGE/Artifacts"
    find Roost.xcframework -type f | LC_ALL=C sort | zip -X -q "$ZIP" -@
)

(
    cd "$DIST"
    find "roost-swift-v$VERSION" -type f | LC_ALL=C sort | zip -X -q "$PACKAGE_ZIP" -@
)

echo "iOS package written to $PACKAGE"
echo "xcframework archive written to $ZIP"
echo "Swift Package archive written to $PACKAGE_ZIP"
