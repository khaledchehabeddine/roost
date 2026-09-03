#!/usr/bin/env bash
#
# Exercise the local v0.15.0 release preflight contract.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
TMP="$(cd "$(mktemp -d)" && pwd -P)"

# GitHub Actions sets this to the branch or pull-request merge ref. The test
# exercises the tag-only gate in isolation.
unset GITHUB_REF_NAME AETHER_RELEASE_TAG AETHER_GITHUB_REPO

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

CHECKOUT="$TMP/checkout"
MOCK_BIN="$TMP/bin"
mkdir -p "$CHECKOUT/scripts/release" "$MOCK_BIN"
cp "$ROOT/scripts/release/verify-release-gates.sh" "$CHECKOUT/scripts/release/"

cat > "$MOCK_BIN/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$1" == "issue" && "$2" == "view" ]]; then
    if [[ $# -ne 9 \
        || "$4" != "--repo" \
        || "$5" != "github.com/RelayNet/aether" \
        || "$6" != "--json" \
        || "$7" != "state" \
        || "$8" != "--jq" \
        || "$9" != ".state" ]]; then
        echo "unexpected release prerequisite query" >&2
        exit 2
    fi
    case "$3" in
        217 | 218 | 219 | 220 | 221 | 222)
            ;;
        *)
            echo "unexpected release prerequisite issue: $3" >&2
            exit 2
            ;;
    esac

    : "${MOCK_GH_LOG:?}"
    echo "$3" >> "$MOCK_GH_LOG"
    if [[ "${MOCK_OPEN_ISSUE:-}" == "$3" ]]; then
        echo "OPEN"
    else
        echo "CLOSED"
    fi
    exit 0
fi

echo "unexpected gh invocation" >&2
exit 2
SH
chmod +x "$MOCK_BIN/gh"
export MOCK_GH_LOG="$TMP/gh.log"

if AETHER_GITHUB_REPO="example.invalid/other/repository" PATH="$MOCK_BIN:$PATH" \
    "$CHECKOUT/scripts/release/verify-release-gates.sh" \
    > "$TMP/repository-override.log" 2>&1; then
    echo "expected a repository override to fail the release gate" >&2
    exit 1
fi
grep -F "repository is fixed to github.com/RelayNet/aether" \
    "$TMP/repository-override.log" >/dev/null
if [[ -e "$MOCK_GH_LOG" ]]; then
    echo "repository override reached GitHub" >&2
    exit 1
fi

if PATH="$MOCK_BIN:$PATH" "$CHECKOUT/scripts/release/verify-release-gates.sh" \
    > "$TMP/missing-notes.log" 2>&1; then
    echo "expected missing release notes to fail the release gate" >&2
    exit 1
fi
grep -F "missing release notes: $CHECKOUT/docs/release-notes/v0.15.0.md" \
    "$TMP/missing-notes.log" >/dev/null

mkdir -p "$CHECKOUT/docs/release-notes"
echo "# Aether v0.15.0" > "$CHECKOUT/docs/release-notes/v0.15.0.md"

if MOCK_OPEN_ISSUE=220 PATH="$MOCK_BIN:$PATH" \
    "$CHECKOUT/scripts/release/verify-release-gates.sh" \
    > "$TMP/open-issue.log" 2>&1; then
    echo "expected an open prerequisite issue to fail the release gate" >&2
    exit 1
fi
grep -F "issue #220 is OPEN, expected CLOSED" "$TMP/open-issue.log" >/dev/null

: > "$MOCK_GH_LOG"
PATH="$MOCK_BIN:$PATH" "$CHECKOUT/scripts/release/verify-release-gates.sh" \
    > "$TMP/complete.log"
grep -F "v0.15.0 release prerequisites are satisfied" "$TMP/complete.log" >/dev/null
printf '%s\n' 217 218 219 220 221 222 > "$TMP/expected-issues.log"
cmp "$TMP/expected-issues.log" "$MOCK_GH_LOG"

echo "release gate verification passed"
