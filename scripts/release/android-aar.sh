#!/usr/bin/env bash
#
# Build the Android AAR and publish it to a local Maven repository layout.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="${AETHER_ANDROID_VERSION:-}"
MAVEN_REPO="${AETHER_ANDROID_MAVEN_REPO:-$ROOT/target/android/maven}"
CENTRAL_DIR="${AETHER_ANDROID_CENTRAL_DIR:-$ROOT/target/android/central}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"
SIGN_PUBLICATION="${AETHER_ANDROID_SIGN_PUBLICATION:-false}"
SIGNING_KEY=""
SIGNING_PASSWORD=""

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

case "$SIGN_PUBLICATION" in
    true | false)
        ;;
    *)
        echo "AETHER_ANDROID_SIGN_PUBLICATION must be true or false" >&2
        exit 2
        ;;
esac

if [[ "$SIGN_PUBLICATION" == "true" ]]; then
    if [[ -z "${AETHER_RELEASE_GPG_PRIVATE_KEY:-}" ]]; then
        echo "missing AETHER_RELEASE_GPG_PRIVATE_KEY" >&2
        exit 2
    fi
    if [[ -z "${AETHER_RELEASE_GPG_PASSPHRASE:-}" ]]; then
        echo "missing AETHER_RELEASE_GPG_PASSPHRASE" >&2
        exit 2
    fi

    SIGNING_KEY="$AETHER_RELEASE_GPG_PRIVATE_KEY"
    SIGNING_PASSWORD="$AETHER_RELEASE_GPG_PASSPHRASE"
fi

unset \
    AETHER_RELEASE_GPG_PRIVATE_KEY \
    AETHER_RELEASE_GPG_PASSPHRASE \
    ORG_GRADLE_PROJECT_aetherSignPublication \
    ORG_GRADLE_PROJECT_signingInMemoryKey \
    ORG_GRADLE_PROJECT_signingInMemoryKeyPassword

cd "$ROOT"
scripts/build/android.sh

rm -rf "$MAVEN_REPO/com/aurelion/aether/$VERSION" "$CENTRAL_DIR"

GRADLE_ARGS=(
    --no-daemon
    -p "$ROOT/packaging/android"
    -PaetherVersion="$VERSION"
    -PaetherMavenRepo="$MAVEN_REPO"
    :aether:publishReleasePublicationToAetherLocalRepository
)

if [[ "$SIGN_PUBLICATION" == "true" ]]; then
    ORG_GRADLE_PROJECT_aetherSignPublication=true \
        ORG_GRADLE_PROJECT_signingInMemoryKey="$SIGNING_KEY" \
        ORG_GRADLE_PROJECT_signingInMemoryKeyPassword="$SIGNING_PASSWORD" \
        "$GRADLE_BIN" "${GRADLE_ARGS[@]}"
else
    "$GRADLE_BIN" "${GRADLE_ARGS[@]}"
fi

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

if [[ "$SIGN_PUBLICATION" == "true" ]]; then
    missing_signature=0
    while IFS= read -r file; do
        case "$file" in
            *.asc | *.md5 | *.sha1 | *.sha256 | *.sha512)
                continue
                ;;
        esac
        if [[ ! -s "$file.asc" ]]; then
            echo "missing Maven publication signature: $file.asc" >&2
            missing_signature=1
        fi
    done < <(find "$ARTIFACT_DIR" -maxdepth 1 -type f | LC_ALL=C sort)
    if [[ "$missing_signature" -ne 0 ]]; then
        exit 1
    fi
fi

if [[ "$SIGN_PUBLICATION" == "true" ]]; then
    CENTRAL_ZIP="$CENTRAL_DIR/aether-$VERSION-maven-central-signed.zip"
else
    CENTRAL_ZIP="$CENTRAL_DIR/aether-$VERSION-maven-central-unsigned.zip"
fi
(
    cd "$CENTRAL_STAGE"
    jar cf "$CENTRAL_ZIP" com
)

echo "Android AAR published to $AAR"
echo "Maven Central bundle written to $CENTRAL_ZIP"
