#!/usr/bin/env bash
#
# Verify release-candidate artifacts with ephemeral signatures and pinned checksums.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IOS_ARTIFACT_DIR="${1:-}"
ANDROID_ARTIFACT_DIR="${2:-}"
OUT="${3:-$ROOT/target/release-candidate-verification/evidence}"

usage() {
    echo "usage: $0 <ios-artifact-dir> <android-artifact-dir> [evidence-dir]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 2
fi

for dir in "$IOS_ARTIFACT_DIR" "$ANDROID_ARTIFACT_DIR"; do
    if [[ ! -d "$dir" ]]; then
        echo "missing artifact directory: $dir" >&2
        exit 2
    fi
done

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
        cat "$matches" >&2
        rm -f "$matches"
        exit 1
    fi
    result="$(sed -n '1p' "$matches")"
    rm -f "$matches"
    printf '%s\n' "$result"
}

artifact_hash() {
    shasum -a 256 "$1" | awk '{ print $1 }'
}

require_tool awk
require_tool cargo
require_tool gpg
require_tool shasum
require_tool tr

VERSION="$(cargo pkgid --manifest-path "$ROOT/crates/aether-uniffi/Cargo.toml")"
VERSION="${VERSION##*#}"

IOS_ZIP="$(one_match "iOS release-candidate artifact for v$VERSION" \
    find "$IOS_ARTIFACT_DIR" -type f -name "Aether-v$VERSION.xcframework.zip")"
ANDROID_AAR="$(one_match "Android release-candidate AAR for v$VERSION" \
    find "$ANDROID_ARTIFACT_DIR" -type f \
        \( -path "*/com/aurelion/aether/$VERSION/aether-$VERSION.aar" \
        -o -name "aether-$VERSION.aar" \))"

rm -rf "$OUT"
mkdir -p "$OUT/artifacts"

IOS_COPY="$OUT/artifacts/$(basename "$IOS_ZIP")"
ANDROID_COPY="$OUT/artifacts/$(basename "$ANDROID_AAR")"
cp "$IOS_ZIP" "$IOS_COPY"
cp "$ANDROID_AAR" "$ANDROID_COPY"

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
FINGERPRINT="$(
    gpg --batch --list-secret-keys --with-colons |
        awk -F: '/^fpr:/ { print $10; exit }'
)"

if [[ -z "$FINGERPRINT" ]]; then
    echo "could not determine ephemeral release-candidate key fingerprint" >&2
    exit 1
fi

PUBLIC_KEY="$OUT/aether-v$VERSION-release-candidate-test-key.asc"
gpg --batch --armor --export "$FINGERPRINT" > "$PUBLIC_KEY"

export AETHER_RELEASE_GPG_FINGERPRINT="$FINGERPRINT"
"$ROOT/scripts/release/sign-artifact.sh" "$IOS_COPY"
"$ROOT/scripts/release/sign-artifact.sh" "$ANDROID_COPY"
"$ROOT/scripts/test/release-artifact-verification.sh" "$IOS_COPY" "$ANDROID_COPY" "$PUBLIC_KEY"

{
    echo "# Release Candidate Artifact Verification Evidence"
    echo
    printf 'version=%s\n' "$VERSION"
    printf 'command=%s\n' "scripts/test/release-candidate-artifact-verification.sh <ios-artifact-dir> <android-artifact-dir>"
    printf 'commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
    printf 'test_key_fingerprint=%s\n' "$FINGERPRINT"
    printf 'ios_artifact=%s\n' "$(basename "$IOS_COPY")"
    printf 'ios_sha256=%s\n' "$(artifact_hash "$IOS_COPY")"
    printf 'android_artifact=%s\n' "$(basename "$ANDROID_COPY")"
    printf 'android_sha256=%s\n' "$(artifact_hash "$ANDROID_COPY")"
    echo "verification=happy path plus signature mismatch, checksum mismatch, and fingerprint mismatch"
    echo "publication=release-candidate evidence only; final signatures and checksums are tag-gated"
} > "$OUT/EVIDENCE.md"

echo "release-candidate artifact verification evidence written to $OUT"
