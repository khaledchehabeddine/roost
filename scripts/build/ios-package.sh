#!/usr/bin/env bash
#
# Build the iOS xcframework and archive it for distribution.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PKGID="$(cargo pkgid --manifest-path "$ROOT/crates/roost-client/Cargo.toml")"
VERSION="${PKGID##*#}"
DIST="$ROOT/target/ios-distribution"
ZIP="$DIST/Roost-v$VERSION.xcframework.zip"

cd "$ROOT"

scripts/build/xcframework.sh

rm -f "$ZIP"
mkdir -p "$DIST"

timestamp="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
stamp="$(date -u -r "$timestamp" +%Y%m%d%H%M.%S)"
find "$ROOT/target/xcframework/Roost.xcframework" -exec touch -h -t "$stamp" {} +

(
    cd "$ROOT/target/xcframework"
    find Roost.xcframework -type f | LC_ALL=C sort | zip -X -q "$ZIP" -@
)

echo "xcframework archive written to $ZIP"
