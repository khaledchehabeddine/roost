#!/usr/bin/env bash
#
# Verify an Android consumer can resolve and exercise the local Maven AAR.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="${AETHER_ANDROID_VERSION:-}"
MAVEN_REPO="${AETHER_ANDROID_MAVEN_REPO:-$ROOT/target/android/maven}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"
DEVICE_TASK="${AETHER_ANDROID_DEVICE_TASK:-:consumer:pixel6Api36DebugAndroidTest}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
fi

AAR="$MAVEN_REPO/com/aurelion/aether/$VERSION/aether-$VERSION.aar"
if [[ ! -s "$AAR" ]]; then
    echo "missing local Maven AAR: $AAR" >&2
    exit 2
fi

if ! command -v "$GRADLE_BIN" >/dev/null 2>&1; then
    echo "missing required tool: $GRADLE_BIN" >&2
    exit 2
fi

"$GRADLE_BIN" \
    --no-daemon \
    -p "$ROOT/packaging/android" \
    -PaetherVersion="$VERSION" \
    -PaetherMavenRepo="$MAVEN_REPO" \
    "$DEVICE_TASK"
