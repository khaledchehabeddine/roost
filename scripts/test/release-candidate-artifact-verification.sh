#!/usr/bin/env bash
#
# Assemble and verify a complete release-candidate packet with an ephemeral signing key.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IOS_ARTIFACT_DIR="${1:-}"
ANDROID_ARTIFACT_DIR="${2:-}"
ANDROID_DISTRIBUTION_DIR="${3:-}"
SBOM_DIR="${4:-}"
EVIDENCE_DIR="${5:-}"
OUT="${6:-$ROOT/target/release-candidate-verification/evidence}"

usage() {
    echo "usage: $0 <ios-artifacts> <android-artifacts> <android-distribution> <sbom> <gate-evidence> [output]" >&2
}

if [[ $# -lt 5 || $# -gt 6 ]]; then
    usage
    exit 2
fi

for dir in \
    "$IOS_ARTIFACT_DIR" \
    "$ANDROID_ARTIFACT_DIR" \
    "$ANDROID_DISTRIBUTION_DIR" \
    "$SBOM_DIR" \
    "$EVIDENCE_DIR"; do
    if [[ ! -d "$dir" ]]; then
        echo "missing release-candidate input directory: $dir" >&2
        exit 2
    fi
done

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

artifact_hash() {
    shasum -a 256 "$1" | awk '{ print $1 }'
}

require_tool awk
require_tool gpg
require_tool shasum

VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
REVISION="${AETHER_RELEASE_SOURCE_REVISION:-$(git -C "$ROOT" rev-parse HEAD)}"
REVISION="$(printf '%s' "$REVISION" | tr '[:upper:]' '[:lower:]')"

case "$OUT" in
    "" | / | . | .. | */. | */..)
        echo "unsafe release-candidate evidence output: $OUT" >&2
        exit 2
        ;;
esac

OUTPUT_ROOT="$(cd "$ROOT/target" && pwd -P)"
OUTPUT_PARENT="$(cd "$(dirname "$OUT")" && pwd -P)"
if [[ "$OUTPUT_PARENT" != "$OUTPUT_ROOT" && "$OUTPUT_PARENT" != "$OUTPUT_ROOT/"* ]]; then
    echo "release-candidate evidence output must stay beneath $OUTPUT_ROOT" >&2
    exit 2
fi

rm -rf "${OUT:?}"
mkdir -p "$OUT"

TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

export GNUPGHOME="$TMP/gnupg"
mkdir -m 700 "$GNUPGHOME"
if command -v gpgconf >/dev/null 2>&1; then
    gpgconf --launch gpg-agent >/dev/null 2>&1 || true
fi

cat > "$TMP/key.conf" <<'KEY'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Aether Release Candidate Verification
Name-Email: release-candidate@example.invalid
Expire-Date: 1d
%no-protection
%commit
KEY

gpg --batch --generate-key "$TMP/key.conf" >/dev/null
AETHER_RELEASE_GPG_FINGERPRINT="$(
    gpg --batch --list-secret-keys --with-colons |
        awk -F: '/^fpr:/ { print $10; exit }'
)"
export AETHER_RELEASE_GPG_FINGERPRINT

if [[ -z "$AETHER_RELEASE_GPG_FINGERPRINT" ]]; then
    echo "could not determine ephemeral release-candidate key fingerprint" >&2
    exit 1
fi

PACKET="$OUT/mobile-release-packet"
AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    "$ROOT/scripts/release/assemble-mobile-release-packet.sh" \
    "$IOS_ARTIFACT_DIR" \
    "$ANDROID_ARTIFACT_DIR" \
    "$ANDROID_DISTRIBUTION_DIR" \
    "$SBOM_DIR" \
    "$EVIDENCE_DIR" \
    "$PACKET"

IOS_ARTIFACT="$PACKET/Aether-v$VERSION.xcframework.zip"
ANDROID_ARTIFACT="$PACKET/aether-$VERSION.aar"
PUBLIC_KEY="$PACKET/aether-v$VERSION-release-key.asc"

"$ROOT/scripts/test/release-artifact-verification.sh" \
    "$IOS_ARTIFACT" \
    "$ANDROID_ARTIFACT" \
    "$PUBLIC_KEY"

{
    echo "# Release Candidate Artifact Verification Evidence"
    echo
    printf 'version=%s\n' "$VERSION"
    printf 'source_revision=%s\n' "$REVISION"
    printf 'command=%s\n' \
        "scripts/test/release-candidate-artifact-verification.sh <ios-artifacts> <android-artifacts> <android-distribution> <sbom> <gate-evidence>"
    printf 'test_key_fingerprint=%s\n' "$AETHER_RELEASE_GPG_FINGERPRINT"
    printf 'ios_artifact=%s\n' "$(basename "$IOS_ARTIFACT")"
    printf 'ios_sha256=%s\n' "$(artifact_hash "$IOS_ARTIFACT")"
    printf 'android_artifact=%s\n' "$(basename "$ANDROID_ARTIFACT")"
    printf 'android_sha256=%s\n' "$(artifact_hash "$ANDROID_ARTIFACT")"
    echo "verification=packet completeness and provenance plus happy and fail-closed artifact paths"
    echo "publication=release-candidate evidence only; final signatures and checksums are tag-gated"
} > "$OUT/EVIDENCE.md"

echo "release-candidate verification evidence written to $OUT"
