#!/usr/bin/env bash
#
# Build the Android AAR and publish it to a local Maven repository layout.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="${AETHER_ANDROID_VERSION:-}"
MAVEN_REPO="${AETHER_ANDROID_MAVEN_REPO:-$ROOT/target/android/maven}"
CENTRAL_DIR="${AETHER_ANDROID_CENTRAL_DIR:-$ROOT/target/android/central}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
fi

if [[ -z "$VERSION" ]]; then
    echo "could not determine workspace version" >&2
    exit 2
fi

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

verify_aar() {
    local aar="$1"
    local pom="$2"
    local tmp

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    grep -q "<version>$VERSION</version>" "$pom"
    unzip -q "$aar" classes.jar -d "$tmp"
    jar tf "$tmp/classes.jar" | grep -q 'com/aurelion/aether/KeyStore.class'

    for entry in \
        "jni/arm64-v8a/libaether.so" \
        "jni/armeabi-v7a/libaether.so" \
        "jni/x86_64/libaether.so"; do
        unzip -l "$aar" "$entry" | grep -q "$entry"
    done
}

require_tool cargo
require_tool cargo-ndk
require_tool "$GRADLE_BIN"
require_tool jar
require_tool unzip

cd "$ROOT"
scripts/build/android.sh

rm -rf "$MAVEN_REPO/com/aurelion/aether/$VERSION" "$CENTRAL_DIR"

"$GRADLE_BIN" \
    --no-daemon \
    -p "$ROOT/packaging/android" \
    -PaetherVersion="$VERSION" \
    -PaetherMavenRepo="$MAVEN_REPO" \
    :aether:publishReleasePublicationToAetherLocalRepository

ARTIFACT_DIR="$MAVEN_REPO/com/aurelion/aether/$VERSION"
AAR="$ARTIFACT_DIR/aether-$VERSION.aar"
POM="$ARTIFACT_DIR/aether-$VERSION.pom"

if [[ ! -s "$AAR" ]]; then
    echo "missing AAR artifact: $AAR" >&2
    exit 1
fi

if [[ ! -s "$POM" ]]; then
    echo "missing POM artifact: $POM" >&2
    exit 1
fi

verify_aar "$AAR" "$POM"

CENTRAL_STAGE="$(mktemp -d)"
trap 'rm -rf "$CENTRAL_STAGE"' EXIT
mkdir -p "$CENTRAL_STAGE/com/aurelion/aether" "$CENTRAL_DIR"
cp -R "$ARTIFACT_DIR" "$CENTRAL_STAGE/com/aurelion/aether/$VERSION"
(
    cd "$CENTRAL_STAGE"
    jar cf "$CENTRAL_DIR/aether-$VERSION-maven-central-unsigned.zip" com
)

echo "Android AAR published to $AAR"
echo "Unsigned Maven Central bundle written to $CENTRAL_DIR/aether-$VERSION-maven-central-unsigned.zip"
