#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
MODE="${1:-}"
OUT="$ROOT/target/release-verification/reproducible-mobile"

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
    git -C "$ROOT" show -s --format=%ct HEAD
}

checkout_archive() {
    local workdir="$1"

    mkdir -p "$workdir"
    git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$workdir"
}

build_artifacts() {
    local workdir="$1"

    (
        cd "$workdir"
        export SOURCE_DATE_EPOCH
        export CARGO_INCREMENTAL=0
        export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$workdir=/aether-source"

        cargo metadata --locked >/dev/null

        case "$MODE" in
            android)
                scripts/build/android.sh
                ;;
            ios)
                scripts/build/xcframework.sh
                ;;
        esac
    )
}

copy_artifacts() {
    local workdir="$1"
    local artifact_dir="$2"

    mkdir -p "$artifact_dir"

    case "$MODE" in
        android)
            local targets=(
                "aarch64-linux-android"
                "armv7-linux-androideabi"
                "x86_64-linux-android"
            )

            for target in "${targets[@]}"; do
                mkdir -p "$artifact_dir/android-libs/$target"
                cp "$workdir/target/$target/release/libaether.so" \
                    "$artifact_dir/android-libs/$target/libaether.so"
            done

            mkdir -p "$artifact_dir/android"
            cp -R "$workdir/target/android/kotlin" "$artifact_dir/android/kotlin"
            ;;
        ios)
            cp -R "$workdir/target/xcframework/Aether.xcframework" \
                "$artifact_dir/Aether.xcframework"
            cp -R "$workdir/target/xcframework/Sources" "$artifact_dir/Sources"
            ;;
    esac
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
    write_manifest "$artifacts" "$pass_dir/SHA256SUMS"
}

SOURCE_DATE_EPOCH="$(commit_timestamp)"
export SOURCE_DATE_EPOCH

rm -rf "$OUT/$MODE"

run_pass 1
run_pass 2

diff -u "$OUT/$MODE/pass-1/SHA256SUMS" "$OUT/$MODE/pass-2/SHA256SUMS"
echo "$MODE artifacts are reproducible"
