#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --quiet -- -D warnings
cargo llvm-cov --workspace --no-report --quiet
cargo llvm-cov report -p hermes-core --fail-under-lines 80 --quiet
cargo llvm-cov report -p hermes-crypto --fail-under-lines 80 --quiet
