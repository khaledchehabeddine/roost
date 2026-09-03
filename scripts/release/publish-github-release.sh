#!/usr/bin/env bash
#
# Publish the final GitHub Release once and verify GitHub made it immutable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ASSET_DIR="${1:-}"
HOST="github.com"
REPOSITORY="RelayNet/aether"
REPO="$HOST/$REPOSITORY"
API_VERSION="2026-03-10"
TAG="${AETHER_RELEASE_TAG:-${GITHUB_REF_NAME:-}}"
EXPECTED_TAG="v0.15.0"
NOTES="$ROOT/docs/release-notes/$EXPECTED_TAG.md"
SOURCE_REVISION="${AETHER_RELEASE_SOURCE_REVISION:-}"
PUBLISH_TOKEN="${GH_TOKEN:-}"
ADMIN_READ_TOKEN="${AETHER_RELEASE_ADMIN_READ_TOKEN:-}"
unset AETHER_RELEASE_ADMIN_READ_TOKEN
MAX_TAG_DEPTH=8

ASSET_NAMES=(
    Aether-v0.15.0.swift-package.zip
    Aether-v0.15.0.xcframework.zip
    Aether-v0.15.0.xcframework.zip.asc
    Aether-v0.15.0.xcframework.zip.sha256
    SHA256SUMS
    SHA256SUMS.asc
    SOURCE
    android-package-consumer.evidence
    android-reproducibility.evidence
    aether-0.15.0.aar
    aether-0.15.0.aar.asc
    aether-0.15.0.aar.sha256
    aether-0.15.0.pom
    aether-0.15.0-maven-central-signed.zip
    aether-uniffi-v0.15.0-sbom.json
    aether-v0.15.0-release-key.asc
    ios-package-consumer.evidence
    ios-reproducibility.evidence
    mobile-release-packet.evidence
    sbom-reproducibility.evidence
)

usage() {
    echo "usage: $0 <release-asset-directory>" >&2
}

github_api() {
    local token="$1"
    local endpoint="$2"
    local filter="$3"
    GH_TOKEN="$token" gh api "$endpoint" \
        --hostname "$HOST" \
        --header "Accept: application/vnd.github+json" \
        --header "X-GitHub-Api-Version: $API_VERSION" \
        --jq "$filter"
}

remote_tag_commit() {
    local object
    local object_type
    local object_sha
    local extra
    local depth=0

    object="$(github_api "$PUBLISH_TOKEN" "repos/$REPOSITORY/git/ref/tags/$TAG" \
        '.object.type + " " + .object.sha')"
    while true; do
        read -r object_type object_sha extra <<< "$object"
        if [[ ! "$object_sha" =~ ^[0-9a-f]{40}$ || -n "$extra" ]]; then
            echo "invalid remote tag object for $TAG" >&2
            return 1
        fi
        case "$object_type" in
            commit)
                printf '%s\n' "$object_sha"
                return 0
                ;;
            tag)
                depth=$((depth + 1))
                if [[ "$depth" -gt "$MAX_TAG_DEPTH" ]]; then
                    echo "remote tag nesting exceeds $MAX_TAG_DEPTH" >&2
                    return 1
                fi
                object="$(github_api "$PUBLISH_TOKEN" "repos/$REPOSITORY/git/tags/$object_sha" \
                    '.object.type + " " + .object.sha')"
                ;;
            *)
                echo "remote tag $TAG does not resolve to a commit" >&2
                return 1
                ;;
        esac
    done
}

verify_remote_tag() {
    local revision
    revision="$(remote_tag_commit)"
    if [[ "$revision" != "$SOURCE_REVISION" ]]; then
        echo "remote tag $TAG source revision mismatch: $revision, expected $SOURCE_REVISION" >&2
        return 1
    fi
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ "${AETHER_GITHUB_REPO+x}" == x ]]; then
    echo "AETHER_GITHUB_REPO is not supported; repository is fixed to $REPO" >&2
    exit 2
fi

if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
    echo "unsupported release tag: ${TAG:-missing}, expected $EXPECTED_TAG" >&2
    exit 2
fi

if [[ ! "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "AETHER_RELEASE_SOURCE_REVISION must be a full lowercase commit SHA" >&2
    exit 2
fi

if [[ -z "$PUBLISH_TOKEN" || -z "$ADMIN_READ_TOKEN" ]]; then
    echo "GH_TOKEN and AETHER_RELEASE_ADMIN_READ_TOKEN are required" >&2
    exit 2
fi

if [[ ! -d "$ASSET_DIR" || -L "$ASSET_DIR" ]]; then
    echo "missing release asset directory: $ASSET_DIR" >&2
    exit 2
fi
ASSET_DIR="$(cd "$ASSET_DIR" && pwd -P)"

if [[ ! -f "$NOTES" || -L "$NOTES" ]]; then
    echo "missing release notes: $NOTES" >&2
    exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "missing required tool: gh" >&2
    exit 2
fi

asset_count="$(find "$ASSET_DIR" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')"
if [[ "$asset_count" -ne "${#ASSET_NAMES[@]}" ]]; then
    echo "release asset directory does not contain the exact mobile release packet" >&2
    exit 2
fi

assets=()
for name in "${ASSET_NAMES[@]}"; do
    asset="$ASSET_DIR/$name"
    if [[ ! -f "$asset" || -L "$asset" ]]; then
        echo "release asset is not a regular file: $asset" >&2
        exit 2
    fi
    assets+=("$asset")
done

packet_revision="$(awk -F= '$1 == "source_revision" { print $2 }' "$ASSET_DIR/SOURCE")"
if [[ "$packet_revision" != "$SOURCE_REVISION" ]]; then
    echo "mobile release packet source revision does not match $SOURCE_REVISION" >&2
    exit 1
fi

AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION=true \
AETHER_REQUIRE_GITHUB_GATE_EVIDENCE=true \
    "$ROOT/scripts/release/verify-mobile-release-packet.sh" "$ASSET_DIR"

if ! immutable_enabled="$(github_api "$ADMIN_READ_TOKEN" \
    "repos/$REPOSITORY/immutable-releases" '.enabled')"; then
    echo "immutable releases are not enabled or cannot be verified for $REPO" >&2
    exit 1
fi
if [[ "$immutable_enabled" != true ]]; then
    echo "immutable releases are not enabled for $REPO" >&2
    exit 1
fi

merge_base="$(github_api "$PUBLISH_TOKEN" \
    "repos/$REPOSITORY/compare/$SOURCE_REVISION...main" '.merge_base_commit.sha')"
if [[ "$merge_base" != "$SOURCE_REVISION" ]]; then
    echo "release source revision is not on remote main: $SOURCE_REVISION" >&2
    exit 1
fi
verify_remote_tag

# The required tag ruleset prevents updates or deletion while gh stages and
# uploads the draft. GitHub applies release immutability only at publication.
GH_TOKEN="$PUBLISH_TOKEN" gh release create "$TAG" "${assets[@]}" \
    --repo "$REPO" \
    --verify-tag \
    --title "$TAG" \
    --notes-file "$NOTES"

is_immutable="$(
    GH_TOKEN="$PUBLISH_TOKEN" gh release view "$TAG" \
        --repo "$REPO" \
        --json isImmutable \
        --jq .isImmutable
)"
if [[ "$is_immutable" != "true" ]]; then
    echo "published GitHub release $TAG is not immutable" >&2
    exit 1
fi
verify_remote_tag

echo "published immutable GitHub release $TAG"
