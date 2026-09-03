#!/usr/bin/env bash
#
# Exercise the one-shot immutable GitHub Release publication contract.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
TMP="$(cd "$(mktemp -d)" && pwd -P)"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

CHECKOUT="$TMP/checkout"
MOCK_BIN="$TMP/bin"
MOCK_STATE="$TMP/release-exists"
MOCK_LOG="$TMP/gh.log"
ASSETS="$CHECKOUT/target/release-assets"

mkdir -p \
    "$CHECKOUT/scripts/release" \
    "$CHECKOUT/docs/release-notes" \
    "$MOCK_BIN" \
    "$ASSETS"
cp "$ROOT/scripts/release/publish-github-release.sh" "$CHECKOUT/scripts/release/"
echo "# Aether v0.15.0" > "$CHECKOUT/docs/release-notes/v0.15.0.md"
echo "artifact" > "$ASSETS/Aether-v0.15.0.xcframework.zip"
echo "checksum" > "$ASSETS/Aether-v0.15.0.xcframework.zip.sha256"

cat > "$MOCK_BIN/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

: "${MOCK_GH_LOG:?}"
: "${MOCK_RELEASE_STATE:?}"
: "${MOCK_ASSET_DIR:?}"
: "${MOCK_RELEASE_NOTES:?}"
printf '%s\n' "$*" >> "$MOCK_GH_LOG"

if [[ "$1" == "release" && "$2" == "create" ]]; then
    if [[ $# -ne 12 \
        || "$3" != "v0.15.0" \
        || "$4" != "$MOCK_ASSET_DIR/Aether-v0.15.0.xcframework.zip" \
        || "$5" != "$MOCK_ASSET_DIR/Aether-v0.15.0.xcframework.zip.sha256" \
        || "$6" != "--repo" \
        || "$7" != "RelayNet/aether" \
        || "$8" != "--verify-tag" \
        || "$9" != "--title" \
        || "${10}" != "v0.15.0" \
        || "${11}" != "--notes-file" \
        || "${12}" != "$MOCK_RELEASE_NOTES" ]]; then
        echo "unexpected release creation request" >&2
        exit 2
    fi
    if [[ -e "$MOCK_RELEASE_STATE" ]]; then
        echo "release already exists" >&2
        exit 1
    fi
    touch "$MOCK_RELEASE_STATE"
    exit 0
fi

if [[ "$1" == "release" && "$2" == "view" ]]; then
    if [[ $# -ne 9 \
        || "$3" != "v0.15.0" \
        || "$4" != "--repo" \
        || "$5" != "RelayNet/aether" \
        || "$6" != "--json" \
        || "$7" != "isImmutable" \
        || "$8" != "--jq" \
        || "$9" != ".isImmutable" ]]; then
        echo "unexpected release immutability query" >&2
        exit 2
    fi
    if [[ ! -e "$MOCK_RELEASE_STATE" ]]; then
        exit 1
    fi
    echo "${MOCK_RELEASE_IMMUTABLE:-true}"
    exit 0
fi

echo "unexpected gh invocation" >&2
exit 2
SH
chmod +x "$MOCK_BIN/gh"

export MOCK_GH_LOG="$MOCK_LOG"
export MOCK_RELEASE_STATE="$MOCK_STATE"
export MOCK_ASSET_DIR="$ASSETS"
export MOCK_RELEASE_NOTES="$CHECKOUT/docs/release-notes/v0.15.0.md"
export AETHER_RELEASE_TAG="v0.15.0"

PATH="$MOCK_BIN:$PATH" \
    "$CHECKOUT/scripts/release/publish-github-release.sh" "$ASSETS" \
    > "$TMP/published.log"
grep -F "published immutable GitHub release v0.15.0" "$TMP/published.log" >/dev/null
grep -F "release create v0.15.0" "$MOCK_LOG" >/dev/null
grep -F "Aether-v0.15.0.xcframework.zip" "$MOCK_LOG" >/dev/null
grep -F "Aether-v0.15.0.xcframework.zip.sha256" "$MOCK_LOG" >/dev/null
grep -F -- "--verify-tag" "$MOCK_LOG" >/dev/null
grep -F -- "--repo RelayNet/aether" "$MOCK_LOG" >/dev/null
grep -F -- "--notes-file $CHECKOUT/docs/release-notes/v0.15.0.md" "$MOCK_LOG" >/dev/null

if PATH="$MOCK_BIN:$PATH" \
    "$CHECKOUT/scripts/release/publish-github-release.sh" "$ASSETS" \
    > "$TMP/existing.log" 2>&1; then
    echo "expected an existing release to block publication" >&2
    exit 1
fi

rm -f "$MOCK_STATE"
if MOCK_RELEASE_IMMUTABLE=false PATH="$MOCK_BIN:$PATH" \
    "$CHECKOUT/scripts/release/publish-github-release.sh" "$ASSETS" \
    > "$TMP/mutable.log" 2>&1; then
    echo "expected a mutable published release to fail verification" >&2
    exit 1
fi
grep -F "published GitHub release v0.15.0 is not immutable" "$TMP/mutable.log" >/dev/null

if grep -E -- '--prerelease|--clobber|release (edit|upload)' "$MOCK_LOG"; then
    echo "publication attempted to create a mutable release or replace existing data" >&2
    exit 1
fi
if [[ "$(grep -c '^release create v0.15.0 ' "$MOCK_LOG")" -ne 3 ]]; then
    echo "publication did not make exactly one create attempt per scenario" >&2
    exit 1
fi
if [[ "$(grep -c '^release view v0.15.0 --repo RelayNet/aether --json isImmutable --jq .isImmutable$' "$MOCK_LOG")" -ne 2 ]]; then
    echo "publication did not verify immutability after each successful create" >&2
    exit 1
fi

echo "release publication verification passed"
