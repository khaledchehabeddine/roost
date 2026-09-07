#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

cd "$ROOT"

cargo metadata --format-version 1 --locked >/dev/null
cargo test --locked -p roost-core --release --test constrained_decryption_budget -- --nocapture
