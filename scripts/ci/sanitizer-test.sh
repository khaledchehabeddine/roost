#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
TARGET="x86_64-unknown-linux-gnu"

usage() {
    echo "usage: $0 <address|memory>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

case "$1" in
    address)
        SANITIZER_FLAGS="-Zsanitizer=address"
        ;;
    memory)
        SANITIZER_FLAGS="-Zsanitizer=memory -Zsanitizer-memory-track-origins"
        ;;
    *)
        usage
        exit 2
        ;;
esac

cd "$ROOT"

# Lockfile freshness guard. Run before exporting the sanitizer flags: this
# invocation resolves to the toolchain pinned in rust-toolchain.toml (stable),
# which rejects the nightly-only -Z sanitizer options that RUSTFLAGS carries.
cargo metadata --locked >/dev/null

export RUSTFLAGS="$SANITIZER_FLAGS"
export RUSTDOCFLAGS="$SANITIZER_FLAGS"

cargo +nightly test \
    --locked \
    -Z build-std \
    --target "$TARGET" \
    -p aether-crypto \
    -p aether-core \
    --features blake3/pure \
    --lib \
    --tests
