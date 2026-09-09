#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --quiet -- -D warnings

cargo llvm-cov --workspace --no-report --quiet
cargo llvm-cov report -p roost-core -p roost-crypto --quiet
