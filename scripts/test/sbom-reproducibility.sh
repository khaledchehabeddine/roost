#!/usr/bin/env bash
#
# Verify the release SBOM is identical across clean checkout paths.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
REVISION="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
TMP="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

for pass in 1 2; do
    work="$TMP/checkout-$pass"
    mkdir -p "$work"
    git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$work"
    cp "$ROOT/scripts/release/sbom.sh" "$work/scripts/release/sbom.sh"
    (
        cd "$work"
        AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
            scripts/release/sbom.sh
    )
done

SBOM_NAME="aether-uniffi-v$VERSION-sbom.json"
SOURCE_NAME="aether-uniffi-v$VERSION-sbom.source"
FIRST="$TMP/checkout-1/target/sbom"
SECOND="$TMP/checkout-2/target/sbom"

cmp "$FIRST/$SBOM_NAME" "$SECOND/$SBOM_NAME"
cmp "$FIRST/$SOURCE_NAME" "$SECOND/$SOURCE_NAME"

if rg -F "$TMP" "$FIRST/$SBOM_NAME"; then
    echo "release SBOM contains its checkout path" >&2
    exit 1
fi

jq -e --arg revision "$REVISION" '
    any(.metadata.properties[]?;
        .name == "aether:source:revision" and .value == $revision)
' "$FIRST/$SBOM_NAME" >/dev/null

echo "release SBOM is reproducible across checkout paths"
