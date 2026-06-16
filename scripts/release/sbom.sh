#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
NAME="aether-uniffi-v0.8.0-sbom"
OUTPUT="$ROOT/target/sbom/$NAME.json"
GENERATED="$ROOT/crates/aether-uniffi/$NAME.json"

cd "$ROOT"

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$ROOT"/crates/*/"$NAME.json" "$OUTPUT"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

cargo metadata --locked >/dev/null

# The default crate mode writes one SBOM with Cargo targets as subcomponents.
cargo cyclonedx \
    --manifest-path crates/aether-uniffi/Cargo.toml \
    --format json \
    --spec-version 1.5 \
    --target all \
    --override-filename "$NAME"

mv "$GENERATED" "$OUTPUT"
rm -f "$ROOT"/crates/*/"$NAME.json"
echo "SBOM written to $OUTPUT"
