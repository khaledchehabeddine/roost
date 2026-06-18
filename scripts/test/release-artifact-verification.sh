#!/usr/bin/env bash
#
# Exercise release artifact verification happy paths and fail-closed negative paths.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IOS_ARTIFACT="${1:-}"
ANDROID_ARTIFACT="${2:-}"
PUBLIC_KEY="${3:-}"

usage() {
    echo "usage: $0 <ios-artifact> <android-artifact> <public-key.asc>" >&2
}

if [[ $# -ne 3 ]]; then
    usage
    exit 2
fi

for artifact in "$IOS_ARTIFACT" "$ANDROID_ARTIFACT"; do
    if [[ ! -f "$artifact" ]]; then
        echo "missing artifact: $artifact" >&2
        exit 2
    fi
    if [[ ! -f "$artifact.asc" ]]; then
        echo "missing signature: $artifact.asc" >&2
        exit 2
    fi
    if [[ ! -f "$artifact.sha256" ]]; then
        echo "missing checksum: $artifact.sha256" >&2
        exit 2
    fi
done

if [[ ! -f "$PUBLIC_KEY" ]]; then
    echo "missing public key: $PUBLIC_KEY" >&2
    exit 2
fi

if [[ -z "${AETHER_RELEASE_GPG_FINGERPRINT:-}" ]]; then
    echo "missing AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

VERIFY="$ROOT/scripts/release/verify-artifact.sh"
TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

expect_failure() {
    local label="$1"
    shift

    if "$@"; then
        echo "$label unexpectedly passed" >&2
        exit 1
    fi
}

signature_mismatch_fails() {
    local artifact="$1"
    local bad="$TMP/$(basename "$artifact").signature-mismatch"

    cp "$artifact" "$bad"
    printf 'tamper' >> "$bad"
    shasum -a 256 "$bad" > "$bad.sha256"

    expect_failure "signature mismatch for $(basename "$artifact")" \
        "$VERIFY" "$bad" "$artifact.asc" "$bad.sha256" "$PUBLIC_KEY"
}

checksum_mismatch_fails() {
    local artifact="$1"
    local bad_checksum="$TMP/$(basename "$artifact").checksum-mismatch.sha256"

    printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' \
        "$(basename "$artifact")" > "$bad_checksum"

    expect_failure "checksum mismatch for $(basename "$artifact")" \
        "$VERIFY" "$artifact" "$artifact.asc" "$bad_checksum" "$PUBLIC_KEY"
}

fingerprint_mismatch_fails() {
    local artifact="$1"
    local wrong_fingerprint="0000000000000000000000000000000000000000"

    expect_failure "fingerprint mismatch for $(basename "$artifact")" \
        env AETHER_RELEASE_GPG_FINGERPRINT="$wrong_fingerprint" \
        "$VERIFY" "$artifact" "$artifact.asc" "$artifact.sha256" "$PUBLIC_KEY"
}

for artifact in "$IOS_ARTIFACT" "$ANDROID_ARTIFACT"; do
    "$VERIFY" "$artifact" "$artifact.asc" "$artifact.sha256" "$PUBLIC_KEY"
    signature_mismatch_fails "$artifact"
    checksum_mismatch_fails "$artifact"
    fingerprint_mismatch_fails "$artifact"
done

echo "release artifact verification passed"
