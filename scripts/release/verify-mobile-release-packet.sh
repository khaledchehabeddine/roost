#!/usr/bin/env bash
#
# Verify the complete mobile release packet against one source revision.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PACKET_INPUT="${1:-}"
REQUIRE_SIGNED_MAVEN="${AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION:-false}"
REQUIRE_GITHUB_EVIDENCE="${AETHER_REQUIRE_GITHUB_GATE_EVIDENCE:-$REQUIRE_SIGNED_MAVEN}"
SAFE_EXTRACT="$ROOT/scripts/release/extract-zip-safely.sh"

usage() {
    echo "usage: $0 <mobile-release-packet-dir>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ ! -d "$PACKET_INPUT" ]]; then
    echo "missing mobile release packet: $PACKET_INPUT" >&2
    exit 2
fi

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

gate_command() {
    case "$1" in
        android-package-consumer)
            echo "scripts/test/android-aar-negative.sh; scripts/test/android-aar-consumer.sh"
            ;;
        android-reproducibility)
            echo "scripts/release/reproducible-mobile-artifacts.sh android"
            ;;
        ios-package-consumer)
            echo "scripts/test/ios-package-consumer.sh <swift-package-archive>"
            ;;
        ios-reproducibility)
            echo "scripts/release/reproducible-mobile-artifacts.sh ios"
            ;;
        mobile-release-packet)
            echo "scripts/test/mobile-release-packet.sh"
            ;;
        sbom-reproducibility)
            echo "scripts/test/sbom-reproducibility.sh"
            ;;
        *)
            return 1
            ;;
    esac
}

verify_evidence() {
    local expected_gate="$1"
    local evidence="$2"
    local expected_keys="$TMP/$expected_gate-expected-keys"
    local actual_keys="$TMP/$expected_gate-actual-keys"
    local provider
    local repository
    local run_id
    local run_attempt
    local job

    printf '%s\n' \
        ci_job \
        ci_provider \
        ci_repository \
        ci_run_attempt \
        ci_run_id \
        command \
        gate \
        result \
        schema_version \
        source_date_epoch \
        source_revision \
        version | LC_ALL=C sort > "$expected_keys"
    awk -F= 'index($0, "=") > 1 { print $1; next } { exit 1 }' "$evidence" |
        LC_ALL=C sort > "$actual_keys"
    if ! diff -u "$expected_keys" "$actual_keys"; then
        echo "$expected_gate evidence does not match the required schema" >&2
        exit 1
    fi

    if [[ "$(source_value schema_version "$evidence")" != 1 \
        || "$(source_value gate "$evidence")" != "$expected_gate" \
        || "$(source_value result "$evidence")" != passed ]]; then
        echo "invalid $expected_gate gate evidence" >&2
        exit 1
    fi
    if [[ "$(source_value version "$evidence")" != "$VERSION" ]]; then
        echo "$expected_gate evidence version mismatch" >&2
        exit 1
    fi
    if [[ "$(source_value source_revision "$evidence" | tr '[:upper:]' '[:lower:]')" \
        != "$EXPECTED_REVISION" ]]; then
        echo "$expected_gate evidence source revision mismatch" >&2
        exit 1
    fi
    if [[ "$(source_value source_date_epoch "$evidence")" != "$SOURCE_EPOCH" ]]; then
        echo "$expected_gate evidence source date epoch mismatch" >&2
        exit 1
    fi
    if [[ "$(source_value command "$evidence")" != "$(gate_command "$expected_gate")" ]]; then
        echo "$expected_gate evidence command mismatch" >&2
        exit 1
    fi

    provider="$(source_value ci_provider "$evidence")"
    repository="$(source_value ci_repository "$evidence")"
    run_id="$(source_value ci_run_id "$evidence")"
    run_attempt="$(source_value ci_run_attempt "$evidence")"
    job="$(source_value ci_job "$evidence")"

    case "$provider" in
        github-actions)
            if [[ "$repository" != RelayNet/aether \
                || ! "$run_id" =~ ^[0-9]+$ \
                || ! "$run_attempt" =~ ^[0-9]+$ ]]; then
                echo "$expected_gate evidence has invalid GitHub Actions identity" >&2
                exit 1
            fi
            case "$expected_gate:$job" in
                android-package-consumer:android-aar-distribution \
                    | android-reproducibility:android-reproducible \
                    | ios-package-consumer:ios-reproducible \
                    | ios-reproducibility:ios-reproducible \
                    | mobile-release-packet:release-candidate-artifact-verification \
                    | mobile-release-packet:signed-release \
                    | sbom-reproducibility:sbom)
                    ;;
                *)
                    echo "$expected_gate evidence has unexpected GitHub Actions job: $job" >&2
                    exit 1
                    ;;
            esac
            ;;
        local)
            if [[ "$REQUIRE_GITHUB_EVIDENCE" == true ]]; then
                echo "$expected_gate requires GitHub Actions evidence" >&2
                exit 1
            fi
            if [[ "$repository" != local \
                || "$run_id" != local \
                || "$run_attempt" != local \
                || "$job" != local ]]; then
                echo "$expected_gate evidence has invalid local identity" >&2
                exit 1
            fi
            ;;
        *)
            echo "$expected_gate evidence has unknown CI provider: $provider" >&2
            exit 1
            ;;
    esac

    if [[ -z "${EVIDENCE_PROVIDER:-}" ]]; then
        EVIDENCE_PROVIDER="$provider"
        EVIDENCE_REPOSITORY="$repository"
        EVIDENCE_RUN_ID="$run_id"
        EVIDENCE_RUN_ATTEMPT="$run_attempt"
    elif [[ "$provider" != "$EVIDENCE_PROVIDER" \
        || "$repository" != "$EVIDENCE_REPOSITORY" \
        || "$run_id" != "$EVIDENCE_RUN_ID" \
        || "$run_attempt" != "$EVIDENCE_RUN_ATTEMPT" ]]; then
        echo "$expected_gate evidence came from a different CI run" >&2
        exit 1
    fi
}

verify_signature() {
    local artifact="$1"
    local signature="$2"
    local status
    local signer

    if ! status="$(
        GNUPGHOME="$VERIFY_HOME" \
            gpg --batch --status-fd 1 --verify "$signature" "$artifact" 2>/dev/null
    )"; then
        echo "signature verification failed for $artifact" >&2
        exit 1
    fi

    signer="$(awk '/^\[GNUPG:\] VALIDSIG / { print $3; exit }' <<<"$status")"
    signer="$(printf '%s' "$signer" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
    if [[ "$signer" != "$EXPECTED_FINGERPRINT" ]]; then
        echo "signature key mismatch for $artifact" >&2
        exit 1
    fi
}

require_tool awk
require_tool cmp
require_tool diff
require_tool find
require_tool gpg
require_tool jq
require_tool shasum
require_tool tr
require_tool unzip

if [[ -z "${AETHER_RELEASE_GPG_FINGERPRINT:-}" ]]; then
    echo "missing AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

EXPECTED_FINGERPRINT="$(
    printf '%s' "$AETHER_RELEASE_GPG_FINGERPRINT" |
        tr -d '[:space:]' |
        tr '[:lower:]' '[:upper:]'
)"
if [[ -z "$EXPECTED_FINGERPRINT" ]]; then
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

PACKET="$(cd "$PACKET_INPUT" && pwd -P)"
IOS_ARTIFACT="$PACKET/Aether-v$VERSION.xcframework.zip"
IOS_PACKAGE="$PACKET/Aether-v$VERSION.swift-package.zip"
ANDROID_ARTIFACT="$PACKET/aether-$VERSION.aar"
ANDROID_POM="$PACKET/aether-$VERSION.pom"
SBOM="$PACKET/aether-uniffi-v$VERSION-sbom.json"
PUBLIC_KEY="$PACKET/aether-v$VERSION-release-key.asc"
SOURCE="$PACKET/SOURCE"
MANIFEST="$PACKET/SHA256SUMS"
MANIFEST_SIGNATURE="$PACKET/SHA256SUMS.asc"
EVIDENCE_GATES=(
    android-package-consumer
    android-reproducibility
    ios-package-consumer
    ios-reproducibility
    mobile-release-packet
    sbom-reproducibility
)
CENTRAL_BUNDLE="$(one_match "Android Maven Central bundle for v$VERSION" \
    find "$PACKET" -maxdepth 1 -type f \
        \( -name "aether-$VERSION-maven-central-signed.zip" \
        -o -name "aether-$VERSION-maven-central-unsigned.zip" \))"
CENTRAL_IS_SIGNED=false
if [[ "$(basename "$CENTRAL_BUNDLE")" == "aether-$VERSION-maven-central-signed.zip" ]]; then
    CENTRAL_IS_SIGNED=true
fi

if [[ "$REQUIRE_SIGNED_MAVEN" == "true" && "$CENTRAL_IS_SIGNED" != "true" ]]; then
    echo "final release requires a signed Android Maven Central bundle" >&2
    exit 1
fi

TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

EXPECTED_FILES="$TMP/expected-files"
ACTUAL_FILES="$TMP/actual-files"
PAYLOAD_FILES="$TMP/payload-files"
MANIFEST_FILES="$TMP/manifest-files"

{
    printf '%s\n' \
        "Aether-v$VERSION.swift-package.zip" \
        "Aether-v$VERSION.xcframework.zip" \
        "Aether-v$VERSION.xcframework.zip.asc" \
        "Aether-v$VERSION.xcframework.zip.sha256" \
        "SHA256SUMS" \
        "SHA256SUMS.asc" \
        "SOURCE" \
        "android-package-consumer.evidence" \
        "android-reproducibility.evidence" \
        "aether-$VERSION.aar" \
        "aether-$VERSION.aar.asc" \
        "aether-$VERSION.aar.sha256" \
        "aether-$VERSION.pom" \
        "$(basename "$CENTRAL_BUNDLE")" \
        "aether-uniffi-v$VERSION-sbom.json" \
        "aether-v$VERSION-release-key.asc" \
        "ios-package-consumer.evidence" \
        "ios-reproducibility.evidence" \
        "mobile-release-packet.evidence" \
        "sbom-reproducibility.evidence"
} | LC_ALL=C sort > "$EXPECTED_FILES"

find "$PACKET" -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort > "$ACTUAL_FILES"
if ! diff -u "$EXPECTED_FILES" "$ACTUAL_FILES"; then
    echo "mobile release packet is incomplete or contains unexpected files" >&2
    exit 1
fi
if find "$PACKET" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
    echo "mobile release packet must contain top-level regular files only" >&2
    find "$PACKET" -mindepth 1 -maxdepth 1 ! -type f -print >&2
    exit 1
fi

VERIFY_HOME="$TMP/gnupg"
mkdir -m 700 "$VERIFY_HOME"
GNUPGHOME="$VERIFY_HOME" gpg --batch --import "$PUBLIC_KEY" >/dev/null
GNUPGHOME="$VERIFY_HOME" \
    gpg --batch --list-keys --with-colons "$EXPECTED_FINGERPRINT" >/dev/null
verify_signature "$MANIFEST" "$MANIFEST_SIGNATURE"

sed '/^SHA256SUMS$/d; /^SHA256SUMS\.asc$/d' "$EXPECTED_FILES" > "$PAYLOAD_FILES"
awk 'NF == 2 { name = $2; sub(/^\*/, "", name); sub(/^\.\//, "", name); print name }' \
    "$MANIFEST" | LC_ALL=C sort > "$MANIFEST_FILES"
if ! diff -u "$PAYLOAD_FILES" "$MANIFEST_FILES"; then
    echo "release packet manifest does not cover the exact payload" >&2
    exit 1
fi

(
    cd "$PACKET"
    shasum -a 256 --check SHA256SUMS
)

"$ROOT/scripts/release/verify-artifact.sh" \
    "$IOS_ARTIFACT" \
    "$IOS_ARTIFACT.asc" \
    "$IOS_ARTIFACT.sha256" \
    "$PUBLIC_KEY"
"$ROOT/scripts/release/verify-artifact.sh" \
    "$ANDROID_ARTIFACT" \
    "$ANDROID_ARTIFACT.asc" \
    "$ANDROID_ARTIFACT.sha256" \
    "$PUBLIC_KEY"

SOURCE_VERSION="$(source_value version "$SOURCE")"
SOURCE_REVISION="$(source_value source_revision "$SOURCE" | tr '[:upper:]' '[:lower:]')"
SOURCE_EPOCH="$(source_value source_date_epoch "$SOURCE")"

if [[ "$SOURCE_VERSION" != "$VERSION" ]]; then
    echo "release packet source version mismatch: $SOURCE_VERSION" >&2
    exit 1
fi
if [[ "$SOURCE_REVISION" != "$EXPECTED_REVISION" ]]; then
    echo "release packet source revision mismatch: $SOURCE_REVISION" >&2
    exit 1
fi
if [[ ! "$SOURCE_EPOCH" =~ ^[0-9]+$ ]]; then
    echo "invalid release packet source date epoch: $SOURCE_EPOCH" >&2
    exit 1
fi

EVIDENCE_PROVIDER=""
EVIDENCE_REPOSITORY=""
EVIDENCE_RUN_ID=""
EVIDENCE_RUN_ATTEMPT=""
for gate in "${EVIDENCE_GATES[@]}"; do
    verify_evidence "$gate" "$PACKET/$gate.evidence"
done

if ! jq -e --arg version "$VERSION" --arg revision "$EXPECTED_REVISION" '
    .bomFormat == "CycloneDX"
    and .metadata.component.name == "aether-uniffi"
    and .metadata.component.version == $version
    and any(.metadata.properties[]?;
        .name == "aether:source:revision" and .value == $revision)
    and any(.components[]?; .name == "aether-core" and .version == $version)
    and any(.components[]?; .name == "aether-crypto" and .version == $version)
' "$SBOM" >/dev/null; then
    echo "SBOM does not describe the v$VERSION mobile binding dependency graph" >&2
    exit 1
fi

grep -Fq '<groupId>com.aurelion</groupId>' "$ANDROID_POM"
grep -Fq '<artifactId>aether</artifactId>' "$ANDROID_POM"
grep -Fq "<version>$VERSION</version>" "$ANDROID_POM"

"$SAFE_EXTRACT" "$CENTRAL_BUNDLE" "$TMP/central"
CENTRAL_DIR="$TMP/central/com/aurelion/aether/$VERSION"
if find "$TMP/central" -type f ! -path "$CENTRAL_DIR/*" -print -quit | grep -q .; then
    echo "Android Maven Central bundle contains unexpected coordinates" >&2
    find "$TMP/central" -type f ! -path "$CENTRAL_DIR/*" -print >&2
    exit 1
fi
if ! cmp -s "$ANDROID_ARTIFACT" "$CENTRAL_DIR/aether-$VERSION.aar"; then
    echo "Android AAR does not match the Maven Central bundle" >&2
    exit 1
fi
if ! cmp -s "$ANDROID_POM" "$CENTRAL_DIR/aether-$VERSION.pom"; then
    echo "Android POM does not match the Maven Central bundle" >&2
    exit 1
fi

if [[ "$CENTRAL_IS_SIGNED" == "true" ]]; then
    while IFS= read -r file; do
        case "$file" in
            *.asc | *.md5 | *.sha1 | *.sha256 | *.sha512)
                continue
                ;;
        esac
        if [[ ! -s "$file.asc" ]]; then
            echo "missing Maven publication signature: $file.asc" >&2
            exit 1
        fi
        verify_signature "$file" "$file.asc"
    done < <(find "$CENTRAL_DIR" -type f | LC_ALL=C sort)
fi

"$SAFE_EXTRACT" "$IOS_ARTIFACT" "$TMP/xcframework"
"$SAFE_EXTRACT" "$IOS_PACKAGE" "$TMP/swift-package"
PACKAGE_DIR="$TMP/swift-package/aether-ios-v$VERSION"
PACKAGE_MANIFEST="$PACKAGE_DIR/Package.swift"

if [[ ! -s "$PACKAGE_MANIFEST" ]]; then
    echo "iOS Distribution Package is missing Package.swift" >&2
    exit 1
fi
if ! find "$PACKAGE_DIR/Sources/Aether" -type f -name '*.swift' -print -quit | grep -q .; then
    echo "iOS Distribution Package is missing generated Swift sources" >&2
    exit 1
fi
grep -Fq '.library(name: "Aether"' "$PACKAGE_MANIFEST"
grep -Fq 'path: "Artifacts/Aether.xcframework"' "$PACKAGE_MANIFEST"

if ! diff -qr \
    "$TMP/xcframework/Aether.xcframework" \
    "$PACKAGE_DIR/Artifacts/Aether.xcframework"; then
    echo "iOS Distribution Package does not contain the signed xcframework bytes" >&2
    exit 1
fi

echo "verified mobile release packet for v$VERSION at $EXPECTED_REVISION"
