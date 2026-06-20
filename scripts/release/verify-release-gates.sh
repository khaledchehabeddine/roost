#!/usr/bin/env bash
#
# Verify release-management gates that must hold before the release is treated as publishable.

set -euo pipefail

REPO="${AETHER_GITHUB_REPO:-RelayNet/aether}"
TAG="${AETHER_RELEASE_TAG:-v1.0.0}"
EXPECTED_TAG="v1.0.0"
# #128 is the umbrella closeout and #189 delivers this script; gate only prerequisite evidence.
REQUIRED_ISSUES=(129 130 131 132 133)

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

if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
    echo "unsupported release tag: $TAG, expected $EXPECTED_TAG" >&2
    exit 2
fi

if [[ -n "${GITHUB_REF_NAME:-}" && "$GITHUB_REF_NAME" != "$EXPECTED_TAG" ]]; then
    echo "unsupported GitHub ref: $GITHUB_REF_NAME, expected $EXPECTED_TAG" >&2
    exit 2
fi

for issue in "${REQUIRED_ISSUES[@]}"; do
    state="$(issue_state "$issue")"
    if [[ "$state" != "CLOSED" ]]; then
        echo "issue #$issue is $state, expected CLOSED" >&2
        exit 1
    fi
done

echo "$TAG release prerequisite issues are closed"
