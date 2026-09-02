#!/usr/bin/env bash
#
# Build the Android AAR and publish it to a local Maven repository layout.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="${AETHER_ANDROID_VERSION:-}"
ARTIFACT_ID="${AETHER_ANDROID_ARTIFACT_ID:-aether}"
MAVEN_REPO="${AETHER_ANDROID_MAVEN_REPO:-$ROOT/target/android/maven}"
CENTRAL_DIR="${AETHER_ANDROID_CENTRAL_DIR:-$ROOT/target/android/central}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"
SIGN_PUBLICATION="${AETHER_ANDROID_SIGN_PUBLICATION:-false}"
SIGNING_KEY=""
SIGNING_PASSWORD=""
SOURCE_REVISION="${AETHER_RELEASE_SOURCE_REVISION:-}"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
fi

if [[ -z "$VERSION" ]]; then
    echo "could not determine workspace version" >&2
    exit 2
fi

if [[ -z "$SOURCE_REVISION" ]]; then
    SOURCE_REVISION="$(git -C "$ROOT" rev-parse HEAD)"
fi
SOURCE_REVISION="$(printf '%s' "$SOURCE_REVISION" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid release source revision: $SOURCE_REVISION" >&2
    exit 2
fi

if [[ -z "$SOURCE_EPOCH" ]]; then
    SOURCE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
fi
if [[ ! "$SOURCE_EPOCH" =~ ^[0-9]+$ ]]; then
    echo "invalid source date epoch: $SOURCE_EPOCH" >&2
    exit 2
fi
export SOURCE_DATE_EPOCH="$SOURCE_EPOCH"

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
    grep -q "<artifactId>$ARTIFACT_ID</artifactId>" "$pom"
    unzip -q "$aar" classes.jar -d "$tmp"
    jar tf "$tmp/classes.jar" | grep -q 'com/aurelion/aether/KeyStore.class'
    if [[ "$ARTIFACT_ID" == "aether-development" ]]; then
        jar tf "$tmp/classes.jar" | grep -q 'com/aurelion/aether/DevelopmentCertificateAuthority.class'
    elif jar tf "$tmp/classes.jar" | grep -q 'com/aurelion/aether/DevelopmentCertificateAuthority.class'; then
        echo "production AAR unexpectedly contains the development certificate authority" >&2
        return 1
    fi

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

case "$ARTIFACT_ID" in
    aether | aether-development)
        ;;
    *)
        echo "AETHER_ANDROID_ARTIFACT_ID must be aether or aether-development" >&2
        exit 2
        ;;
esac

if [[ "$ARTIFACT_ID" == "aether-development" \
    && "${AETHER_CARGO_FEATURES:-}" != *development-certificates* ]]; then
    echo "aether-development requires the development-certificates Cargo feature" >&2
    exit 2
fi

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

rm -rf "$MAVEN_REPO/com/aurelion/$ARTIFACT_ID/$VERSION"
mkdir -p "$CENTRAL_DIR"
find "$CENTRAL_DIR" -maxdepth 1 -type f \
    -name "$ARTIFACT_ID-$VERSION-maven-central-*.zip" -delete

GRADLE_ARGS=(
    --no-daemon
    -p "$ROOT/packaging/android"
    -PaetherVersion="$VERSION"
    -PaetherArtifactId="$ARTIFACT_ID"
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

ARTIFACT_DIR="$MAVEN_REPO/com/aurelion/$ARTIFACT_ID/$VERSION"
AAR="$ARTIFACT_DIR/$ARTIFACT_ID-$VERSION.aar"
POM="$ARTIFACT_DIR/$ARTIFACT_ID-$VERSION.pom"

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
mkdir -p "$CENTRAL_STAGE/com/aurelion/$ARTIFACT_ID" "$CENTRAL_DIR"
cp -R "$ARTIFACT_DIR" "$CENTRAL_STAGE/com/aurelion/$ARTIFACT_ID/$VERSION"

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
    CENTRAL_ZIP="$CENTRAL_DIR/$ARTIFACT_ID-$VERSION-maven-central-signed.zip"
else
    CENTRAL_ZIP="$CENTRAL_DIR/$ARTIFACT_ID-$VERSION-maven-central-unsigned.zip"
fi
(
    cd "$CENTRAL_STAGE"
    jar cf "$CENTRAL_ZIP" com
)

SOURCE_RECORD="$CENTRAL_DIR/$ARTIFACT_ID-$VERSION-maven-central.source"
printf 'version=%s\nsource_revision=%s\nsource_date_epoch=%s\n' \
    "$VERSION" "$SOURCE_REVISION" "$SOURCE_EPOCH" > "$SOURCE_RECORD"

echo "Android AAR published to $AAR"
echo "Maven Central bundle written to $CENTRAL_ZIP"
echo "Android distribution source record written to $SOURCE_RECORD"
