#!/usr/bin/env bash
#
# Verify release-management gates that must hold before the release is treated as publishable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REPO="${AETHER_GITHUB_REPO:-RelayNet/aether}"
TAG="${AETHER_RELEASE_TAG:-}"
REQUIRED_ISSUES=(128 129 130 131 132 133 189)

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

if [[ -z "$TAG" ]]; then
    require_tool cargo
    pkgid="$(cargo pkgid --manifest-path "$ROOT/crates/aether-uniffi/Cargo.toml")"
    TAG="v${pkgid##*#}"
fi

for issue in "${REQUIRED_ISSUES[@]}"; do
    state="$(issue_state "$issue")"
    if [[ "$state" != "CLOSED" ]]; then
        echo "issue #$issue is $state, expected CLOSED" >&2
        exit 1
    fi
done

echo "$TAG release prerequisite issues are closed"
