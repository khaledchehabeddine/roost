#!/usr/bin/env bash
#
# Assemble, sign, and verify one mobile release packet from pinned build outputs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IOS_INPUT="${1:-}"
ANDROID_INPUT="${2:-}"
ANDROID_DISTRIBUTION_INPUT="${3:-}"
SBOM_INPUT="${4:-}"
EVIDENCE_INPUT="${5:-}"
OUTPUT_INPUT="${6:-$ROOT/target/mobile-release-packet}"
OUTPUT_ROOT_INPUT="${AETHER_RELEASE_OUTPUT_ROOT:-$ROOT/target}"
REQUIRE_SIGNED_MAVEN="${AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION:-false}"
REQUIRE_GITHUB_EVIDENCE="${AETHER_REQUIRE_GITHUB_GATE_EVIDENCE:-$REQUIRE_SIGNED_MAVEN}"

usage() {
    echo "usage: $0 <ios-artifacts> <android-artifacts> <android-distribution> <sbom> <evidence> [output]" >&2
}

if [[ $# -lt 5 || $# -gt 6 ]]; then
    usage
    exit 2
fi

for input in \
    "$IOS_INPUT" \
    "$ANDROID_INPUT" \
    "$ANDROID_DISTRIBUTION_INPUT" \
    "$SBOM_INPUT" \
    "$EVIDENCE_INPUT"; do
    if [[ ! -d "$input" ]]; then
        echo "missing release packet input directory: $input" >&2
        exit 2
    fi
done

case "$REQUIRE_SIGNED_MAVEN" in
    true | false)
        ;;
    *)
        echo "AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION must be true or false" >&2
        exit 2
        ;;
esac
case "$REQUIRE_GITHUB_EVIDENCE" in
    true | false)
        ;;
    *)
        echo "AETHER_REQUIRE_GITHUB_GATE_EVIDENCE must be true or false" >&2
        exit 2
        ;;
esac

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

one_match() {
    local label="$1"
    shift
    local matches
    local count
    local result

    matches="$(mktemp)"
    "$@" | LC_ALL=C sort > "$matches"
    count="$(wc -l < "$matches" | tr -d '[:space:]')"
    if [[ "$count" -ne 1 ]]; then
        echo "expected exactly one $label, found $count" >&2
        sed -n '1,20p' "$matches" >&2
        rm -f "$matches"
        exit 1
    fi
    result="$(sed -n '1p' "$matches")"
    rm -f "$matches"
    printf '%s\n' "$result"
}

source_value() {
    local key="$1"
    local source="$2"
    local values
    local count

    values="$(awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2) }' "$source")"
    count="$(printf '%s\n' "$values" | awk 'NF { count += 1 } END { print count + 0 }')"
    if [[ "$count" -ne 1 ]]; then
        echo "expected exactly one $key in $source, found $count" >&2
        exit 1
    fi
    printf '%s\n' "$values"
}

verify_source() {
    local label="$1"
    local source="$2"
    local version
    local revision
    local epoch

    version="$(source_value version "$source")"
    revision="$(source_value source_revision "$source" | tr '[:upper:]' '[:lower:]')"
    epoch="$(source_value source_date_epoch "$source")"

    if [[ "$version" != "$VERSION" ]]; then
        echo "$label version mismatch: $version, expected $VERSION" >&2
        exit 1
    fi
    if [[ "$revision" != "$EXPECTED_REVISION" ]]; then
        echo "$label source revision mismatch: $revision, expected $EXPECTED_REVISION" >&2
        exit 1
    fi
    if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
        echo "$label has invalid source date epoch: $epoch" >&2
        exit 1
    fi

    if [[ -z "$SOURCE_EPOCH" ]]; then
        SOURCE_EPOCH="$epoch"
    elif [[ "$epoch" != "$SOURCE_EPOCH" ]]; then
        echo "$label source date epoch mismatch: $epoch, expected $SOURCE_EPOCH" >&2
        exit 1
    fi
}

verify_evidence() {
    local expected_gate="$1"
    local evidence="$2"
    local schema
    local gate
    local result
    local version
    local revision
    local epoch

    schema="$(source_value schema_version "$evidence")"
    gate="$(source_value gate "$evidence")"
    result="$(source_value result "$evidence")"
    version="$(source_value version "$evidence")"
    revision="$(source_value source_revision "$evidence" | tr '[:upper:]' '[:lower:]')"
    epoch="$(source_value source_date_epoch "$evidence")"

    if [[ "$schema" != 1 || "$gate" != "$expected_gate" || "$result" != passed ]]; then
        echo "invalid $expected_gate gate evidence: $evidence" >&2
        exit 1
    fi
    if [[ "$version" != "$VERSION" ]]; then
        echo "$expected_gate evidence version mismatch: $version, expected $VERSION" >&2
        exit 1
    fi
    if [[ "$revision" != "$EXPECTED_REVISION" ]]; then
        echo "$expected_gate evidence source revision mismatch: $revision, expected $EXPECTED_REVISION" >&2
        exit 1
    fi
    if [[ "$epoch" != "$SOURCE_EPOCH" ]]; then
        echo "$expected_gate evidence source date epoch mismatch: $epoch, expected $SOURCE_EPOCH" >&2
        exit 1
    fi
}

sign_manifest() {
    local manifest="$1"
    local gpg_args=(
        --batch
        --yes
        --armor
        --detach-sign
        --output "$manifest.asc"
        --local-user "$SIGNING_FINGERPRINT"
    )

    if [[ -n "${AETHER_RELEASE_GPG_PASSPHRASE:-}" ]]; then
        printf '%s' "$AETHER_RELEASE_GPG_PASSPHRASE" |
            gpg "${gpg_args[@]}" --pinentry-mode loopback --passphrase-fd 0 "$manifest"
    else
        gpg "${gpg_args[@]}" "$manifest"
    fi
}

require_tool awk
require_tool find
require_tool gpg
require_tool shasum
require_tool tr

if [[ -z "${AETHER_RELEASE_GPG_FINGERPRINT:-}" ]]; then
    echo "missing AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

SIGNING_FINGERPRINT="$(
    printf '%s' "$AETHER_RELEASE_GPG_FINGERPRINT" |
        tr -d '[:space:]' |
        tr '[:lower:]' '[:upper:]'
)"
if [[ -z "$SIGNING_FINGERPRINT" ]]; then
    echo "empty AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
if [[ -z "$VERSION" ]]; then
    echo "could not determine workspace version" >&2
    exit 2
fi

EXPECTED_REVISION="${AETHER_RELEASE_SOURCE_REVISION:-$(git -C "$ROOT" rev-parse HEAD)}"
EXPECTED_REVISION="$(printf '%s' "$EXPECTED_REVISION" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid expected source revision: $EXPECTED_REVISION" >&2
    exit 2
fi

IOS_ARTIFACT="$(one_match "iOS xcframework archive for v$VERSION" \
    find "$IOS_INPUT" -type f -name "Aether-v$VERSION.xcframework.zip")"
IOS_PACKAGE="$(one_match "iOS Distribution Package for v$VERSION" \
    find "$IOS_INPUT" -type f -name "Aether-v$VERSION.swift-package.zip")"
IOS_SOURCE="$(one_match "iOS source record" find "$IOS_INPUT" -type f -name SOURCE)"
ANDROID_ARTIFACT="$(one_match "Android AAR for v$VERSION" \
    find "$ANDROID_INPUT" -type f -name "aether-$VERSION.aar")"
ANDROID_POM="$(one_match "Android POM for v$VERSION" \
    find "$ANDROID_INPUT" -type f -name "aether-$VERSION.pom")"
ANDROID_SOURCE="$(one_match "Android source record" find "$ANDROID_INPUT" -type f -name SOURCE)"
CENTRAL_BUNDLE="$(one_match "Android Maven Central bundle for v$VERSION" \
    find "$ANDROID_DISTRIBUTION_INPUT" -type f \
        \( -name "aether-$VERSION-maven-central-signed.zip" \
        -o -name "aether-$VERSION-maven-central-unsigned.zip" \))"
CENTRAL_SOURCE="$(one_match "Android distribution source record" \
    find "$ANDROID_DISTRIBUTION_INPUT" -type f \
        -name "aether-$VERSION-maven-central.source")"
SBOM="$(one_match "SBOM for v$VERSION" \
    find "$SBOM_INPUT" -type f -name "roost-client-v$VERSION-sbom.json")"
SBOM_SOURCE="$(one_match "SBOM source record" \
    find "$SBOM_INPUT" -type f -name "roost-client-v$VERSION-sbom.source")"

EVIDENCE_GATES=(
    android-package-consumer
    android-reproducibility
    ios-package-consumer
    ios-reproducibility
    mobile-release-packet
    sbom-reproducibility
)
EVIDENCE_FILES=()
for gate in "${EVIDENCE_GATES[@]}"; do
    evidence="$(one_match "$gate gate evidence" \
        find "$EVIDENCE_INPUT" -type f -name "$gate.evidence")"
    EVIDENCE_FILES+=("$evidence")
done

if [[ "$REQUIRE_SIGNED_MAVEN" == "true" \
    && "$(basename "$CENTRAL_BUNDLE")" != "aether-$VERSION-maven-central-signed.zip" ]]; then
    echo "final release requires a signed Android Maven Central bundle" >&2
    exit 1
fi

SOURCE_EPOCH=""
verify_source "iOS artifacts" "$IOS_SOURCE"
verify_source "Android artifacts" "$ANDROID_SOURCE"
verify_source "Android distribution" "$CENTRAL_SOURCE"
verify_source "SBOM" "$SBOM_SOURCE"
for index in "${!EVIDENCE_GATES[@]}"; do
    verify_evidence "${EVIDENCE_GATES[$index]}" "${EVIDENCE_FILES[$index]}"
done

OUTPUT_NAME="$(basename "$OUTPUT_INPUT")"
case "$OUTPUT_INPUT" in
    "" | / | . | .. | */. | */..)
        echo "unsafe mobile release packet output: $OUTPUT_INPUT" >&2
        exit 2
        ;;
esac
case "$OUTPUT_NAME" in
    "" | . | ..)
        echo "unsafe mobile release packet output: $OUTPUT_INPUT" >&2
        exit 2
        ;;
esac

case "$OUTPUT_ROOT_INPUT" in
    "" | / | . | .. | */. | */..)
        echo "unsafe mobile release output root: $OUTPUT_ROOT_INPUT" >&2
        exit 2
        ;;
esac
if [[ ! -d "$OUTPUT_ROOT_INPUT" ]]; then
    echo "missing mobile release output root: $OUTPUT_ROOT_INPUT" >&2
    exit 2
fi
if [[ ! -d "$(dirname "$OUTPUT_INPUT")" ]]; then
    echo "missing mobile release output parent: $(dirname "$OUTPUT_INPUT")" >&2
    exit 2
fi

OUTPUT_ROOT="$(cd "$OUTPUT_ROOT_INPUT" && pwd -P)"
OUTPUT_PARENT="$(cd "$(dirname "$OUTPUT_INPUT")" && pwd -P)"
if [[ "$OUTPUT_PARENT" != "$OUTPUT_ROOT" && "$OUTPUT_PARENT" != "$OUTPUT_ROOT/"* ]]; then
    echo "mobile release packet output must stay beneath $OUTPUT_ROOT" >&2
    exit 2
fi

OUTPUT="$OUTPUT_PARENT/$OUTPUT_NAME"
STAGE="$(mktemp -d "$OUTPUT_PARENT/.mobile-release-packet.XXXXXX")"
BACKUP=""

cleanup() {
    if [[ -n "${STAGE:-}" && -d "$STAGE" ]]; then
        rm -rf "${STAGE:?}"
    fi
    if [[ -n "${BACKUP:-}" && -d "$BACKUP" ]]; then
        if [[ ! -e "$OUTPUT" && ! -L "$OUTPUT" && -e "$BACKUP/previous" ]]; then
            mv "$BACKUP/previous" "$OUTPUT" || true
        fi
        rm -rf "${BACKUP:?}"
    fi
}
trap cleanup EXIT

cp "$IOS_ARTIFACT" "$STAGE/Aether-v$VERSION.xcframework.zip"
cp "$IOS_PACKAGE" "$STAGE/Aether-v$VERSION.swift-package.zip"
cp "$ANDROID_ARTIFACT" "$STAGE/aether-$VERSION.aar"
cp "$ANDROID_POM" "$STAGE/aether-$VERSION.pom"
cp "$CENTRAL_BUNDLE" "$STAGE/"
cp "$SBOM" "$STAGE/roost-client-v$VERSION-sbom.json"
for index in "${!EVIDENCE_GATES[@]}"; do
    cp "${EVIDENCE_FILES[$index]}" "$STAGE/${EVIDENCE_GATES[$index]}.evidence"
done

printf 'version=%s\nsource_revision=%s\nsource_date_epoch=%s\n' \
    "$VERSION" "$EXPECTED_REVISION" "$SOURCE_EPOCH" > "$STAGE/SOURCE"

"$ROOT/scripts/release/sign-artifact.sh" "$STAGE/Aether-v$VERSION.xcframework.zip"
"$ROOT/scripts/release/sign-artifact.sh" "$STAGE/aether-$VERSION.aar"

PUBLIC_KEY="$STAGE/aether-v$VERSION-release-key.asc"
gpg --batch --armor --export "$SIGNING_FINGERPRINT" > "$PUBLIC_KEY"
if [[ ! -s "$PUBLIC_KEY" ]]; then
    echo "could not export release public key: $SIGNING_FINGERPRINT" >&2
    exit 1
fi

MANIFEST_TEMP="$(mktemp)"
(
    cd "$STAGE"
    find . -maxdepth 1 -type f |
        LC_ALL=C sort |
        while IFS= read -r file; do
            shasum -a 256 "$file"
        done > "$MANIFEST_TEMP"
    mv "$MANIFEST_TEMP" SHA256SUMS
)
sign_manifest "$STAGE/SHA256SUMS"

AETHER_RELEASE_SOURCE_REVISION="$EXPECTED_REVISION" \
AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION="$REQUIRE_SIGNED_MAVEN" \
AETHER_REQUIRE_GITHUB_GATE_EVIDENCE="$REQUIRE_GITHUB_EVIDENCE" \
    "$ROOT/scripts/release/verify-mobile-release-packet.sh" "$STAGE"

if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
    BACKUP="$(mktemp -d "$OUTPUT_PARENT/.mobile-release-packet.backup.XXXXXX")"
    mv "$OUTPUT" "$BACKUP/previous"
fi

if ! mv "$STAGE" "$OUTPUT"; then
    echo "could not install mobile release packet at $OUTPUT" >&2
    exit 1
fi
STAGE=""

if [[ -n "$BACKUP" ]]; then
    rm -rf "${BACKUP:?}"
    BACKUP=""
fi

echo "mobile release packet written to $OUTPUT"
