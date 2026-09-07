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
MOCK_AUDIT_LOG="$TMP/gh-audit.log"
ASSETS="$CHECKOUT/target/release-assets"
REVISION="1111111111111111111111111111111111111111"
OTHER_REVISION="3333333333333333333333333333333333333333"

unset AETHER_GITHUB_REPO

mkdir -p \
    "$CHECKOUT/scripts/release" \
    "$CHECKOUT/docs/release-notes" \
    "$MOCK_BIN" \
    "$ASSETS"
cp "$ROOT/scripts/release/publish-github-release.sh" "$CHECKOUT/scripts/release/"
echo "# Aether v0.15.0" > "$CHECKOUT/docs/release-notes/v0.15.0.md"
for name in \
    Aether-v0.15.0.swift-package.zip \
    Aether-v0.15.0.xcframework.zip \
    Aether-v0.15.0.xcframework.zip.asc \
    Aether-v0.15.0.xcframework.zip.sha256 \
    SHA256SUMS SHA256SUMS.asc SOURCE \
    android-package-consumer.evidence android-reproducibility.evidence \
    aether-0.15.0.aar aether-0.15.0.aar.asc aether-0.15.0.aar.sha256 \
    aether-0.15.0.pom aether-0.15.0-maven-central-signed.zip \
    roost-client-v0.15.0-sbom.json aether-v0.15.0-release-key.asc \
    ios-package-consumer.evidence ios-reproducibility.evidence \
    mobile-release-packet.evidence sbom-reproducibility.evidence; do
    echo "fixture" > "$ASSETS/$name"
done
printf 'source_revision=%s\n' "$REVISION" > "$ASSETS/SOURCE"

cat > "$CHECKOUT/scripts/release/verify-mobile-release-packet.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 \
    || "$1" != "$MOCK_ASSET_DIR" \
    || "$AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION" != true \
    || "$AETHER_REQUIRE_GITHUB_GATE_EVIDENCE" != true ]]; then
    echo "unexpected final packet verification request" >&2
    exit 2
fi
echo "verify-packet $1" >> "$MOCK_GH_LOG"
if [[ "$MOCK_PACKET_VALID" != true ]]; then
    echo "packet verification failed" >&2
    exit 1
fi
SH
chmod +x "$CHECKOUT/scripts/release/verify-mobile-release-packet.sh"

cat > "$MOCK_BIN/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

: "${MOCK_GH_LOG:?}"
: "${MOCK_GH_AUDIT_LOG:?}"
: "${MOCK_RELEASE_STATE:?}"
: "${MOCK_ASSET_DIR:?}"
: "${MOCK_RELEASE_NOTES:?}"
printf '%s\n' "$*" >> "$MOCK_GH_LOG"
printf '%s\n' "$*" >> "$MOCK_GH_AUDIT_LOG"

if [[ "$1" == "api" ]]; then
    if [[ $# -ne 10 \
        || "$3" != "--hostname" \
        || "$4" != "github.com" \
        || "$5" != "--header" \
        || "$6" != "Accept: application/vnd.github+json" \
        || "$7" != "--header" \
        || "$8" != "X-GitHub-Api-Version: 2026-03-10" \
        || "$9" != "--jq" ]]; then
        echo "unexpected GitHub API request" >&2
        exit 2
    fi
    case "$2" in
        repos/RelayNet/aether/immutable-releases)
            if [[ "$GH_TOKEN" != "admin-read-token" || "${10}" != ".enabled" ]]; then
                echo "unexpected repository immutability query" >&2
                exit 2
            fi
            if [[ "$MOCK_IMMUTABLE_QUERY_FAIL" == true ]]; then
                echo "immutable releases unavailable" >&2
                exit 1
            fi
            echo "$MOCK_IMMUTABLE_ENABLED"
            exit 0
            ;;
        "repos/RelayNet/aether/compare/$AETHER_RELEASE_SOURCE_REVISION...main")
            if [[ "$GH_TOKEN" != "publish-token" || "${10}" != ".merge_base_commit.sha" ]]; then
                echo "unexpected main ancestry query" >&2
                exit 2
            fi
            if [[ "$MOCK_SOURCE_ON_MAIN" == true ]]; then
                echo "$AETHER_RELEASE_SOURCE_REVISION"
            else
                echo "3333333333333333333333333333333333333333"
            fi
            exit 0
            ;;
        repos/RelayNet/aether/git/ref/tags/v0.15.0)
            if [[ "$GH_TOKEN" != "publish-token" || "${10}" != '.object.type + " " + .object.sha' ]]; then
                echo "unexpected remote tag query" >&2
                exit 2
            fi
            if [[ "$MOCK_TAG_TYPE" == tag ]]; then
                echo "tag 2222222222222222222222222222222222222222"
            else
                echo "$MOCK_TAG_TYPE $MOCK_TAG_REVISION"
            fi
            exit 0
            ;;
        repos/RelayNet/aether/git/tags/2222222222222222222222222222222222222222)
            if [[ "$GH_TOKEN" != "publish-token" || "${10}" != '.object.type + " " + .object.sha' ]]; then
                echo "unexpected annotated tag query" >&2
                exit 2
            fi
            echo "commit $MOCK_TAG_REVISION"
            exit 0
            ;;
    esac
    echo "unexpected GitHub API endpoint: $2" >&2
    exit 2
fi

if [[ "$1" == "release" && "$2" == "create" ]]; then
    if [[ "$GH_TOKEN" != "publish-token" || "$3" != "v0.15.0" ]]; then
        echo "unexpected release creation target or token" >&2
        exit 2
    fi
    shift 3
    for name in \
        Aether-v0.15.0.swift-package.zip \
        Aether-v0.15.0.xcframework.zip \
        Aether-v0.15.0.xcframework.zip.asc \
        Aether-v0.15.0.xcframework.zip.sha256 \
        SHA256SUMS SHA256SUMS.asc SOURCE \
        android-package-consumer.evidence android-reproducibility.evidence \
        aether-0.15.0.aar aether-0.15.0.aar.asc aether-0.15.0.aar.sha256 \
        aether-0.15.0.pom aether-0.15.0-maven-central-signed.zip \
        roost-client-v0.15.0-sbom.json aether-v0.15.0-release-key.asc \
        ios-package-consumer.evidence ios-reproducibility.evidence \
        mobile-release-packet.evidence sbom-reproducibility.evidence; do
        if [[ "$1" != "$MOCK_ASSET_DIR/$name" ]]; then
            echo "unexpected release asset: $1, expected $name" >&2
            exit 2
        fi
        shift
    done
    if [[ $# -ne 7 \
        || "$1" != "--repo" \
        || "$2" != "github.com/RelayNet/aether" \
        || "$3" != "--verify-tag" \
        || "$4" != "--title" \
        || "$5" != "v0.15.0" \
        || "$6" != "--notes-file" \
        || "$7" != "$MOCK_RELEASE_NOTES" ]]; then
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
        || "$5" != "github.com/RelayNet/aether" \
        || "$6" != "--json" \
        || "$7" != "isImmutable" \
        || "$8" != "--jq" \
        || "$9" != ".isImmutable" \
        || "$GH_TOKEN" != "publish-token" ]]; then
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
export MOCK_GH_AUDIT_LOG="$MOCK_AUDIT_LOG"
export MOCK_RELEASE_STATE="$MOCK_STATE"
export MOCK_ASSET_DIR="$ASSETS"
export MOCK_RELEASE_NOTES="$CHECKOUT/docs/release-notes/v0.15.0.md"
export MOCK_IMMUTABLE_ENABLED=true
export MOCK_IMMUTABLE_QUERY_FAIL=false
export MOCK_SOURCE_ON_MAIN=true
export MOCK_TAG_TYPE=tag
export MOCK_TAG_REVISION="$REVISION"
export MOCK_RELEASE_IMMUTABLE=true
export MOCK_PACKET_VALID=true
export AETHER_RELEASE_TAG="v0.15.0"
export AETHER_RELEASE_SOURCE_REVISION="$REVISION"
export GH_TOKEN="publish-token"
export AETHER_RELEASE_ADMIN_READ_TOKEN="admin-read-token"

publish() {
    env PATH="$MOCK_BIN:$PATH" "$@" \
        "$CHECKOUT/scripts/release/publish-github-release.sh" "$ASSETS"
}

expect_blocked_before_create() {
    local scenario="$1"
    local message="$2"
    shift 2
    : > "$MOCK_LOG"
    if publish "$@" > "$TMP/$scenario.log" 2>&1; then
        echo "expected $scenario to block publication" >&2
        exit 1
    fi
    grep -F "$message" "$TMP/$scenario.log" >/dev/null
    if grep -q '^release create ' "$MOCK_LOG"; then
        echo "$scenario reached release creation" >&2
        exit 1
    fi
}

publish > "$TMP/published.log"
grep -F "published immutable GitHub release v0.15.0" "$TMP/published.log" >/dev/null
grep -F "release create v0.15.0" "$MOCK_LOG" >/dev/null
grep -F "Aether-v0.15.0.xcframework.zip" "$MOCK_LOG" >/dev/null
grep -F "Aether-v0.15.0.xcframework.zip.sha256" "$MOCK_LOG" >/dev/null
grep -F -- "--verify-tag" "$MOCK_LOG" >/dev/null
grep -F -- "--repo github.com/RelayNet/aether" "$MOCK_LOG" >/dev/null
grep -F -- "--notes-file $CHECKOUT/docs/release-notes/v0.15.0.md" "$MOCK_LOG" >/dev/null

if [[ "$(grep -c '^api repos/RelayNet/aether/git/ref/tags/v0.15.0 ' "$MOCK_LOG")" -ne 2 ]]; then
    echo "publication did not check the remote tag before and after creation" >&2
    exit 1
fi

if publish > "$TMP/existing.log" 2>&1; then
    echo "expected an existing release to block publication" >&2
    exit 1
fi
grep -F "release already exists" "$TMP/existing.log" >/dev/null

rm -f "$MOCK_STATE"
expect_blocked_before_create disabled-immutability \
    "immutable releases are not enabled for github.com/RelayNet/aether" \
    MOCK_IMMUTABLE_ENABLED=false
expect_blocked_before_create inaccessible-immutability \
    "immutable releases are not enabled or cannot be verified" \
    MOCK_IMMUTABLE_QUERY_FAIL=true
expect_blocked_before_create repository-override \
    "repository is fixed to github.com/RelayNet/aether" \
    AETHER_GITHUB_REPO=example.invalid/other/repository
expect_blocked_before_create missing-admin-token \
    "GH_TOKEN and AETHER_RELEASE_ADMIN_READ_TOKEN are required" \
    AETHER_RELEASE_ADMIN_READ_TOKEN=
expect_blocked_before_create invalid-packet \
    "packet verification failed" \
    MOCK_PACKET_VALID=false
expect_blocked_before_create invalid-source-revision \
    "AETHER_RELEASE_SOURCE_REVISION must be a full lowercase commit SHA" \
    AETHER_RELEASE_SOURCE_REVISION=short
expect_blocked_before_create source-not-on-main \
    "release source revision is not on remote main" \
    MOCK_SOURCE_ON_MAIN=false
expect_blocked_before_create moved-tag \
    "remote tag v0.15.0 source revision mismatch" \
    "MOCK_TAG_REVISION=$OTHER_REVISION"
expect_blocked_before_create non-commit-tag \
    "remote tag v0.15.0 does not resolve to a commit" \
    MOCK_TAG_TYPE=tree

printf 'source_revision=%s\n' "$OTHER_REVISION" > "$ASSETS/SOURCE"
expect_blocked_before_create wrong-packet-source \
    "mobile release packet source revision does not match"
printf 'source_revision=%s\n' "$REVISION" > "$ASSETS/SOURCE"

touch "$ASSETS/.unexpected"
expect_blocked_before_create unexpected-asset \
    "release asset directory does not contain the exact mobile release packet"
rm "$ASSETS/.unexpected"

mv "$ASSETS/Aether-v0.15.0.xcframework.zip" "$TMP/artifact"
ln -s "$TMP/artifact" "$ASSETS/Aether-v0.15.0.xcframework.zip"
expect_blocked_before_create symlink-asset "release asset is not a regular file"
rm "$ASSETS/Aether-v0.15.0.xcframework.zip"
mv "$TMP/artifact" "$ASSETS/Aether-v0.15.0.xcframework.zip"

: > "$MOCK_LOG"
publish MOCK_TAG_TYPE=commit > "$TMP/lightweight-tag.log"
grep -F "published immutable GitHub release v0.15.0" "$TMP/lightweight-tag.log" >/dev/null
rm -f "$MOCK_STATE"

if publish MOCK_RELEASE_IMMUTABLE=false > "$TMP/mutable.log" 2>&1; then
    echo "expected a mutable published release to fail verification" >&2
    exit 1
fi
grep -F "published GitHub release v0.15.0 is not immutable" "$TMP/mutable.log" >/dev/null

if grep -E -- '--prerelease|--clobber|release (edit|upload|delete)' "$MOCK_AUDIT_LOG"; then
    echo "publication attempted to create a mutable release or replace existing data" >&2
    exit 1
fi
if [[ "$(grep -c '^release create v0.15.0 ' "$MOCK_LOG")" -ne 2 ]]; then
    echo "publication did not make one create attempt per permitted scenario" >&2
    exit 1
fi
if [[ "$(grep -c '^release view v0.15.0 --repo github.com/RelayNet/aether --json isImmutable --jq .isImmutable$' "$MOCK_LOG")" -ne 2 ]]; then
    echo "publication did not verify immutability after each successful create" >&2
    exit 1
fi

echo "release publication verification passed"
