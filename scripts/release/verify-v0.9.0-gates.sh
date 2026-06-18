#!/usr/bin/env bash
#
# Verify release-management gates that must hold before v0.9.0 is treated as publishable.

set -euo pipefail

REPO="${AETHER_GITHUB_REPO:-RelayNet/aether}"
TAG="${AETHER_RELEASE_TAG:-v0.9.0}"
REQUIRED_ISSUES=(121 122 123 124 126)

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

for issue in "${REQUIRED_ISSUES[@]}"; do
    state="$(issue_state "$issue")"
    if [[ "$state" != "CLOSED" ]]; then
        echo "issue #$issue is $state, expected CLOSED" >&2
        exit 1
    fi
done

echo "$TAG release prerequisite issues are closed"
