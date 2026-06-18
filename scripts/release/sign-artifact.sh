#!/usr/bin/env bash
#
# Sign one release artifact and write its pinned SHA-256 checksum.

set -euo pipefail

ARTIFACT_INPUT="${1:-}"

usage() {
    echo "usage: $0 <artifact>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ ! -f "$ARTIFACT_INPUT" ]]; then
    echo "missing artifact: $ARTIFACT_INPUT" >&2
    exit 2
fi

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

require_tool gpg
require_tool shasum
require_tool tr

if [[ -z "${AETHER_RELEASE_GPG_FINGERPRINT:-}" ]]; then
    echo "missing AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

SIGNING_FINGERPRINT="$(
    printf '%s' "$AETHER_RELEASE_GPG_FINGERPRINT" |
        tr -d '[:space:]' |
        tr '[:lower:]' '[:upper:]'
)"

if [[ -z "$SIGNING_FINGERPRINT" ]]; then
    echo "empty AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

ARTIFACT_DIR="$(cd "$(dirname "$ARTIFACT_INPUT")" && pwd -P)"
ARTIFACT_NAME="$(basename "$ARTIFACT_INPUT")"

(
    cd "$ARTIFACT_DIR"

    rm -f "$ARTIFACT_NAME.asc" "$ARTIFACT_NAME.sha256"
    shasum -a 256 "$ARTIFACT_NAME" > "$ARTIFACT_NAME.sha256"

    gpg_args=(
        --batch
        --yes
        --armor
        --detach-sign
        --output "$ARTIFACT_NAME.asc"
        --local-user "$SIGNING_FINGERPRINT"
    )

    if [[ -n "${AETHER_RELEASE_GPG_PASSPHRASE:-}" ]]; then
        printf '%s' "$AETHER_RELEASE_GPG_PASSPHRASE" |
            gpg "${gpg_args[@]}" --pinentry-mode loopback --passphrase-fd 0 "$ARTIFACT_NAME"
    else
        gpg "${gpg_args[@]}" "$ARTIFACT_NAME"
    fi
)

echo "signed $ARTIFACT_DIR/$ARTIFACT_NAME"
echo "wrote $ARTIFACT_DIR/$ARTIFACT_NAME.asc"
echo "wrote $ARTIFACT_DIR/$ARTIFACT_NAME.sha256"
