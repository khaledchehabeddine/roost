#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PKGID="$(cargo pkgid --manifest-path "$ROOT/crates/roost-client/Cargo.toml")"
VERSION="${PKGID##*#}"
NAME="roost-client-v$VERSION-sbom"
OUTPUT="$ROOT/target/sbom/$NAME.json"
GENERATED="$ROOT/crates/roost-client/$NAME.json"
SOURCE_OUTPUT="$ROOT/target/sbom/$NAME.source"
SOURCE_REVISION="${AETHER_RELEASE_SOURCE_REVISION:-}"

cd "$ROOT"

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$ROOT"/crates/*/"$NAME.json" "$OUTPUT" "$SOURCE_OUTPUT"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

if [[ -z "$SOURCE_REVISION" ]]; then
    SOURCE_REVISION="$(git rev-parse HEAD)"
fi
SOURCE_REVISION="$(printf '%s' "$SOURCE_REVISION" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid release source revision: $SOURCE_REVISION" >&2
    exit 2
fi

cargo metadata --locked --format-version 1 >/dev/null

# The default crate mode writes one SBOM with Cargo targets as subcomponents.
cargo cyclonedx \
    --manifest-path crates/roost-client/Cargo.toml \
    --format json \
    --spec-version 1.5 \
    --target all \
    --override-filename "$NAME"

NORMALIZED="$(mktemp "$ROOT/target/sbom/.sbom.XXXXXX")"
cleanup() {
    rm -f "$NORMALIZED"
}
trap cleanup EXIT

jq --arg root "$ROOT" --arg revision "$SOURCE_REVISION" '
    walk(
        if type == "string" then
            (split($root) | join("/aether-source"))
        else
            .
        end
    )
    | .metadata.properties = (
        ((.metadata.properties // [])
            | map(select(.name != "aether:source:revision")))
        + [{"name": "aether:source:revision", "value": $revision}]
    )
' "$GENERATED" > "$NORMALIZED"

mv "$NORMALIZED" "$OUTPUT"
rm -f "$ROOT"/crates/*/"$NAME.json"
printf 'version=%s\nsource_revision=%s\nsource_date_epoch=%s\n' \
    "$VERSION" "$SOURCE_REVISION" "$SOURCE_DATE_EPOCH" > "$SOURCE_OUTPUT"

echo "SBOM written to $OUTPUT"
echo "SBOM source record written to $SOURCE_OUTPUT"
