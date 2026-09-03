#!/usr/bin/env bash
#
# Publish the final GitHub Release once and verify GitHub made it immutable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ASSET_DIR="${1:-}"
REPO="${AETHER_GITHUB_REPO:-RelayNet/aether}"
TAG="${AETHER_RELEASE_TAG:-${GITHUB_REF_NAME:-}}"
EXPECTED_TAG="v0.15.0"
NOTES="$ROOT/docs/release-notes/$EXPECTED_TAG.md"

usage() {
    echo "usage: $0 <release-asset-directory>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
    echo "unsupported release tag: ${TAG:-missing}, expected $EXPECTED_TAG" >&2
    exit 2
fi

if [[ ! -d "$ASSET_DIR" ]]; then
    echo "missing release asset directory: $ASSET_DIR" >&2
    exit 2
fi

if [[ ! -f "$NOTES" ]]; then
    echo "missing release notes: $NOTES" >&2
    exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "missing required tool: gh" >&2
    exit 2
fi

shopt -s nullglob
assets=("$ASSET_DIR"/*)
shopt -u nullglob

if [[ ${#assets[@]} -eq 0 ]]; then
    echo "release asset directory is empty: $ASSET_DIR" >&2
    exit 2
fi

for asset in "${assets[@]}"; do
    if [[ ! -f "$asset" ]]; then
        echo "release asset is not a regular file: $asset" >&2
        exit 2
    fi
done

gh release create "$TAG" "${assets[@]}" \
    --repo "$REPO" \
    --verify-tag \
    --title "$TAG" \
    --notes-file "$NOTES"

is_immutable="$(
    gh release view "$TAG" \
        --repo "$REPO" \
        --json isImmutable \
        --jq .isImmutable
)"
if [[ "$is_immutable" != "true" ]]; then
    echo "published GitHub release $TAG is not immutable" >&2
    exit 1
fi

echo "published immutable GitHub release $TAG"
