#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --quiet -- -D warnings

# Before the test run rather than after it, because this is the one check here
# that a green `cargo test` cannot stand in for: the tests exercise the core
# directly, where the behaviour is already right, and say nothing about whether
# a binding carries it. Text-only, so it costs nothing to run first.
"$(dirname "$0")/../test/uniffi-surface.sh"
cargo llvm-cov --workspace --no-report --quiet
cargo llvm-cov report -p roost-core --fail-under-lines 80 --quiet
cargo llvm-cov report -p roost-crypto --fail-under-lines 80 --quiet
