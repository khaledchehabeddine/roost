#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --quiet -- -D warnings
cargo llvm-cov --workspace --no-report --quiet
cargo llvm-cov report -p aether-core --fail-under-lines 80 --quiet
cargo llvm-cov report -p aether-crypto --fail-under-lines 80 --quiet
