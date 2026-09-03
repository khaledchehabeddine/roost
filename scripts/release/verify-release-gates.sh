#!/usr/bin/env bash
#
# Verify release-management gates that must hold before the release is treated as publishable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REPO="github.com/RelayNet/aether"
TAG="${AETHER_RELEASE_TAG:-v0.15.0}"
EXPECTED_TAG="v0.15.0"
RELEASE_NOTES="$ROOT/docs/release-notes/$TAG.md"
# #223 performs the human-authorized publication; gate the completed implementation work.
REQUIRED_ISSUES=(217 218 219 220 221 222)

usage() {
    echo "usage: $0" >&2
}

if [[ $# -ne 0 ]]; then
    usage
    exit 2
fi

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

issue_state() {
    gh issue view "$1" --repo "$REPO" --json state --jq .state
}

require_tool gh

if [[ "${AETHER_GITHUB_REPO+x}" == x ]]; then
    echo "AETHER_GITHUB_REPO is not supported; repository is fixed to $REPO" >&2
    exit 2
fi

if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
    echo "unsupported release tag: $TAG, expected $EXPECTED_TAG" >&2
    exit 2
fi

if [[ -n "${GITHUB_REF_NAME:-}" && "$GITHUB_REF_NAME" != "$EXPECTED_TAG" ]]; then
    echo "unsupported GitHub ref: $GITHUB_REF_NAME, expected $EXPECTED_TAG" >&2
    exit 2
fi

if [[ ! -f "$RELEASE_NOTES" ]]; then
    echo "missing release notes: $RELEASE_NOTES" >&2
    exit 1
fi

for issue in "${REQUIRED_ISSUES[@]}"; do
    state="$(issue_state "$issue")"
    if [[ "$state" != "CLOSED" ]]; then
        echo "issue #$issue is $state, expected CLOSED" >&2
        exit 1
    fi
done

echo "$TAG release prerequisites are satisfied"
