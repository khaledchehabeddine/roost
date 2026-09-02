#!/usr/bin/env bash
#
# Record one successful mobile release gate in the packet evidence schema.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OUTPUT="${1:-}"
GATE="${2:-}"

usage() {
    echo "usage: $0 <output.evidence> <gate>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

case "$GATE" in
    android-package-consumer)
        COMMAND="scripts/test/android-aar-negative.sh; scripts/test/android-aar-consumer.sh"
        ;;
    android-reproducibility)
        COMMAND="scripts/release/reproducible-mobile-artifacts.sh android"
        ;;
    ios-package-consumer)
        COMMAND="scripts/test/ios-package-consumer.sh <swift-package-archive>"
        ;;
    ios-reproducibility)
        COMMAND="scripts/release/reproducible-mobile-artifacts.sh ios"
        ;;
    mobile-release-packet)
        COMMAND="scripts/test/mobile-release-packet.sh"
        ;;
    sbom-reproducibility)
        COMMAND="scripts/test/sbom-reproducibility.sh"
        ;;
    *)
        echo "unknown mobile release gate: $GATE" >&2
        exit 2
        ;;
esac

VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
REVISION="${AETHER_RELEASE_SOURCE_REVISION:-$(git -C "$ROOT" rev-parse HEAD)}"
REVISION="$(printf '%s' "$REVISION" | tr '[:upper:]' '[:lower:]')"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct "$REVISION")}"

if [[ -z "$VERSION" ]]; then
    echo "could not determine workspace version" >&2
    exit 2
fi
if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "invalid evidence source revision: $REVISION" >&2
    exit 2
fi
if [[ ! "$SOURCE_EPOCH" =~ ^[0-9]+$ ]]; then
    echo "invalid evidence source date epoch: $SOURCE_EPOCH" >&2
    exit 2
fi

EVIDENCE_PROVIDER="${AETHER_GATE_EVIDENCE_PROVIDER:-}"
case "$EVIDENCE_PROVIDER" in
    "")
        if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
            EVIDENCE_PROVIDER=github-actions
        else
            EVIDENCE_PROVIDER=local
        fi
        ;;
    github-actions | local)
        ;;
    *)
        echo "AETHER_GATE_EVIDENCE_PROVIDER must be github-actions or local" >&2
        exit 2
        ;;
esac

if [[ "$EVIDENCE_PROVIDER" == github-actions ]]; then
    CI_PROVIDER=github-actions
    CI_REPOSITORY="${GITHUB_REPOSITORY:-}"
    CI_RUN_ID="${GITHUB_RUN_ID:-}"
    CI_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}"
    CI_JOB="${GITHUB_JOB:-}"

    if [[ "$CI_REPOSITORY" != RelayNet/aether ]]; then
        echo "unexpected evidence repository: $CI_REPOSITORY" >&2
        exit 2
    fi
    if [[ ! "$CI_RUN_ID" =~ ^[0-9]+$ || ! "$CI_RUN_ATTEMPT" =~ ^[0-9]+$ ]]; then
        echo "invalid GitHub Actions run identity" >&2
        exit 2
    fi
    if [[ ! "$CI_JOB" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "invalid GitHub Actions job identity: $CI_JOB" >&2
        exit 2
    fi
else
    CI_PROVIDER=local
    CI_REPOSITORY=local
    CI_RUN_ID=local
    CI_RUN_ATTEMPT=local
    CI_JOB=local
fi

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
TEMP="$(mktemp "$OUTPUT_DIR/.mobile-gate-evidence.XXXXXX")"
cleanup() {
    rm -f "$TEMP"
}
trap cleanup EXIT

printf '%s\n' \
    "schema_version=1" \
    "gate=$GATE" \
    "result=passed" \
    "version=$VERSION" \
    "source_revision=$REVISION" \
    "source_date_epoch=$SOURCE_EPOCH" \
    "command=$COMMAND" \
    "ci_provider=$CI_PROVIDER" \
    "ci_repository=$CI_REPOSITORY" \
    "ci_run_id=$CI_RUN_ID" \
    "ci_run_attempt=$CI_RUN_ATTEMPT" \
    "ci_job=$CI_JOB" > "$TEMP"

mv "$TEMP" "$OUTPUT"
TEMP=""

echo "mobile release gate evidence written to $OUTPUT"
