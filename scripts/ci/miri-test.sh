#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

cd "$ROOT"

cargo metadata --locked >/dev/null
cargo +nightly miri setup
cargo +nightly miri test --locked -p roost-protocol --features blake3/pure --lib
cargo +nightly miri test --locked -p roost-crypto --lib
cargo +nightly miri test --locked -p roost-core --features blake3/pure --lib
