#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
MODE="${1:-}"
OUT="$ROOT/target/release-verification/reproducible-mobile"
ARCHIVE_REF="${AETHER_REPRO_ARCHIVE_REF:-HEAD}"
COMMAND="scripts/release/reproducible-mobile-artifacts.sh $MODE"

usage() {
    echo "usage: $0 <android|ios>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

case "$MODE" in
    android | ios)
        ;;
    *)
        usage
        exit 2
        ;;
esac

commit_timestamp() {
    if git -C "$ROOT" cat-file -e "$ARCHIVE_REF^{commit}" 2>/dev/null; then
        git -C "$ROOT" show -s --format=%ct "$ARCHIVE_REF"
    else
        git -C "$ROOT" show -s --format=%ct HEAD
    fi
}

archive_object() {
    git -C "$ROOT" rev-parse "$ARCHIVE_REF^{object}"
}

archive_commit() {
    if git -C "$ROOT" cat-file -e "$ARCHIVE_REF^{commit}" 2>/dev/null; then
        git -C "$ROOT" rev-parse "$ARCHIVE_REF^{commit}"
    else
        git -C "$ROOT" rev-parse HEAD
    fi
}

checkout_archive() {
    local workdir="$1"

    mkdir -p "$workdir"
    git -C "$ROOT" archive --format=tar "$ARCHIVE_REF" | tar -xf - -C "$workdir"
}

build_artifacts() {
    local workdir="$1"

    (
        cd "$workdir"
        export SOURCE_DATE_EPOCH
        export CARGO_INCREMENTAL=0
        export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$workdir=/aether-source"

        cargo metadata --locked --format-version 1 >/dev/null

        case "$MODE" in
            android)
                scripts/release/android-aar.sh
                ;;
            ios)
                scripts/build/ios-package.sh
                ;;
        esac
    )
}

package_version() {
    local workdir="$1"
    local pkgid

    pkgid="$(cargo pkgid --manifest-path "$workdir/crates/roost-client/Cargo.toml")"
    echo "${pkgid##*#}"
}

copy_artifacts() {
    local workdir="$1"
    local artifact_dir="$2"
    local version

    mkdir -p "$artifact_dir"
    version="$(package_version "$workdir")"
    printf 'version=%s\nsource_revision=%s\nsource_date_epoch=%s\narchive_ref=%s\narchive_object=%s\n' \
        "$version" "$ARCHIVE_COMMIT" "$SOURCE_DATE_EPOCH" "$ARCHIVE_REF" "$ARCHIVE_OBJECT" \
        > "$artifact_dir/SOURCE"

    case "$MODE" in
        android)
            local targets=(
                "aarch64-linux-android"
                "armv7-linux-androideabi"
                "x86_64-linux-android"
            )

            for target in "${targets[@]}"; do
                mkdir -p "$artifact_dir/android-libs/$target"
                cp "$workdir/target/$target/release/libroost_client.so" \
                    "$artifact_dir/android-libs/$target/libroost_client.so"
            done

            mkdir -p "$artifact_dir/android"
            cp -R "$workdir/target/android/kotlin" "$artifact_dir/android/kotlin"

            local maven_artifact_dir
            maven_artifact_dir="$workdir/target/android/maven/com/aurelion/aether/$version"

            mkdir -p "$artifact_dir/android-aar"
            cp "$maven_artifact_dir/aether-$version.aar" "$artifact_dir/android-aar/"
            cp "$maven_artifact_dir/aether-$version.pom" "$artifact_dir/android-aar/"
            ;;
        ios)
            cp -R "$workdir/target/xcframework/Aether.xcframework" \
                "$artifact_dir/Aether.xcframework"
            cp -R "$workdir/target/xcframework/Sources" "$artifact_dir/Sources"
            cp -R "$workdir/target/ios-distribution/aether-ios-v$version" \
                "$artifact_dir/aether-ios-v$version"
            cp "$workdir/target/ios-distribution/Aether-v$version.xcframework.zip" \
                "$artifact_dir/Aether-v$version.xcframework.zip"
            cp "$workdir/target/ios-distribution/Aether-v$version.swift-package.zip" \
                "$artifact_dir/Aether-v$version.swift-package.zip"
            ;;
    esac
}

tool_line() {
    local label="$1"
    shift

    if command -v "$1" >/dev/null 2>&1; then
        local value
        value="$("$@" 2>&1 | awk 'NF { print; exit }' || true)"
        printf '%s=%s\n' "$label" "$value"
    else
        printf '%s=missing\n' "$label"
    fi
}

write_evidence() {
    local artifact_dir="$1"
    local evidence="$artifact_dir/EVIDENCE.md"

    {
        echo "# Reproducible Mobile Artifact Evidence"
        echo
        printf 'mode=%s\n' "$MODE"
        printf 'command=%s\n' "$COMMAND"
        printf 'archive_ref=%s\n' "$ARCHIVE_REF"
        printf 'archive_object=%s\n' "$ARCHIVE_OBJECT"
        printf 'archive_commit=%s\n' "$ARCHIVE_COMMIT"
        printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
        echo "artifact_hashes=../SHA256SUMS"
        echo
        echo "## Environment"
        printf 'uname=%s\n' "$(uname -srm)"
        tool_line git git --version
        tool_line cargo cargo --version
        tool_line rustc rustc --version
        case "$MODE" in
            android)
                tool_line cargo_ndk cargo ndk --version
                tool_line gradle "${GRADLE_BIN:-gradle}" --version
                printf 'ANDROID_HOME=%s\n' "${ANDROID_HOME:-}"
                printf 'ANDROID_NDK_HOME=%s\n' "${ANDROID_NDK_HOME:-}"
                printf 'ANDROID_NDK_ROOT=%s\n' "${ANDROID_NDK_ROOT:-}"
                ;;
            ios)
                tool_line xcodebuild xcodebuild -version
                ;;
        esac
    } > "$evidence"
}

write_manifest() {
    local artifact_dir="$1"
    local manifest="$2"

    (
        cd "$artifact_dir"
        find . -type f |
            LC_ALL=C sort |
            while IFS= read -r file; do
                shasum -a 256 "$file"
            done
    ) > "$manifest"
}

run_pass() {
    local pass="$1"
    local pass_dir="$OUT/$MODE/pass-$pass"
    local workdir="$pass_dir/work"
    local artifacts="$pass_dir/artifacts"

    mkdir -p "$pass_dir"
    checkout_archive "$workdir"
    build_artifacts "$workdir"
    copy_artifacts "$workdir" "$artifacts"
    write_evidence "$artifacts"
    write_manifest "$artifacts" "$pass_dir/SHA256SUMS"
}

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(commit_timestamp)}"
export SOURCE_DATE_EPOCH
ARCHIVE_OBJECT="$(archive_object)"
ARCHIVE_COMMIT="$(archive_commit)"
PINNED_REVISION="${AETHER_RELEASE_SOURCE_REVISION:-$ARCHIVE_COMMIT}"
PINNED_REVISION="$(printf '%s' "$PINNED_REVISION" | tr '[:upper:]' '[:lower:]')"

if [[ "$PINNED_REVISION" != "$ARCHIVE_COMMIT" ]]; then
    echo "release source revision mismatch: $PINNED_REVISION, archived $ARCHIVE_COMMIT" >&2
    exit 2
fi
export AETHER_RELEASE_SOURCE_REVISION="$ARCHIVE_COMMIT"

if [[ -n "${GITHUB_ACTIONS:-}" && "$ARCHIVE_REF" != "HEAD" ]]; then
    echo "AETHER_REPRO_ARCHIVE_REF is local-only and must not be set in GitHub Actions" >&2
    exit 2
fi

rm -rf "${OUT:?}/$MODE"
echo "$MODE archive object: $ARCHIVE_OBJECT"

run_pass 1
run_pass 2

diff -u "$OUT/$MODE/pass-1/SHA256SUMS" "$OUT/$MODE/pass-2/SHA256SUMS"
echo "$MODE artifacts are reproducible"
