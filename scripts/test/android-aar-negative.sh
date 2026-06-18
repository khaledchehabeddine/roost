#!/usr/bin/env bash
#
# Verify consumer resolution fails closed for a missing AAR artifact.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="${AETHER_ANDROID_VERSION:-}"
SOURCE_REPO="${AETHER_ANDROID_MAVEN_REPO:-$ROOT/target/android/maven}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
fi

if ! command -v "$GRADLE_BIN" >/dev/null 2>&1; then
    echo "missing required tool: $GRADLE_BIN" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp -R "$SOURCE_REPO" "$TMP/maven"
ARTIFACT_DIR="$TMP/maven/com/aurelion/aether/$VERSION"
find "$ARTIFACT_DIR" -name "aether-$VERSION.aar" -delete

if "$GRADLE_BIN" \
    --no-daemon \
    -p "$ROOT/packaging/android" \
    -PaetherVersion="$VERSION" \
    -PaetherMavenRepo="$TMP/maven" \
    :consumer:assembleDebugAndroidTest; then
    echo "consumer verification unexpectedly succeeded without the AAR" >&2
    exit 1
fi

echo "consumer verification failed as expected without the AAR"
