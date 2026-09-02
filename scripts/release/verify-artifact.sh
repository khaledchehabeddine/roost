#!/usr/bin/env bash
#
# Verify one release artifact against a detached OpenPGP signature and pinned checksum.

set -euo pipefail

ARTIFACT="${1:-}"
SIGNATURE="${2:-}"
CHECKSUM="${3:-}"
PUBLIC_KEY="${4:-}"

usage() {
    echo "usage: $0 <artifact> <artifact.asc> <artifact.sha256> <public-key.asc>" >&2
}

if [[ $# -ne 4 ]]; then
    usage
    exit 2
fi

for file in "$ARTIFACT" "$SIGNATURE" "$CHECKSUM" "$PUBLIC_KEY"; do
    if [[ ! -f "$file" ]]; then
        echo "missing file: $file" >&2
        exit 2
    fi
done

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

require_tool awk
require_tool gpg
require_tool shasum
require_tool tr

if [[ -z "${AETHER_RELEASE_GPG_FINGERPRINT:-}" ]]; then
    echo "missing AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

EXPECTED_FINGERPRINT="$(
    printf '%s' "$AETHER_RELEASE_GPG_FINGERPRINT" |
        tr -d '[:space:]' |
        tr '[:lower:]' '[:upper:]'
)"

if [[ -z "$EXPECTED_FINGERPRINT" ]]; then
    echo "empty AETHER_RELEASE_GPG_FINGERPRINT" >&2
    exit 2
fi

CHECKSUM_LINES="$(awk 'NF { count += 1 } END { print count + 0 }' "$CHECKSUM")"
CHECKSUM_FIELDS="$(awk 'NF { print NF; exit }' "$CHECKSUM")"
EXPECTED="$(awk 'NF { print $1; exit }' "$CHECKSUM")"
PINNED_NAME="$(awk 'NF { print $2; exit }' "$CHECKSUM")"
PINNED_NAME="${PINNED_NAME#\*}"
ACTUAL="$(shasum -a 256 "$ARTIFACT" | awk '{ print $1 }')"

if [[ "$CHECKSUM_LINES" -ne 1 || "$CHECKSUM_FIELDS" -ne 2 || -z "$EXPECTED" ]]; then
    echo "invalid checksum file: $CHECKSUM" >&2
    exit 1
fi

if [[ "$PINNED_NAME" != "$(basename "$ARTIFACT")" ]]; then
    echo "checksum filename mismatch for $ARTIFACT" >&2
    exit 1
fi

if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    echo "checksum mismatch for $ARTIFACT" >&2
    exit 1
fi

GNUPG_VERIFY_HOME="$(mktemp -d)"
cleanup() {
    rm -rf "$GNUPG_VERIFY_HOME"
}
trap cleanup EXIT
chmod 700 "$GNUPG_VERIFY_HOME"

GNUPGHOME="$GNUPG_VERIFY_HOME" gpg --batch --import "$PUBLIC_KEY" >/dev/null
GNUPGHOME="$GNUPG_VERIFY_HOME" \
    gpg --batch --list-keys --with-colons "$EXPECTED_FINGERPRINT" >/dev/null
if ! VERIFY_STATUS="$(
    GNUPGHOME="$GNUPG_VERIFY_HOME" \
        gpg --batch --status-fd 1 --verify "$SIGNATURE" "$ARTIFACT" 2>/dev/null
)"; then
    echo "signature verification failed for $ARTIFACT" >&2
    exit 1
fi

SIGNER_FINGERPRINT="$(awk '/^\[GNUPG:\] VALIDSIG / { print $3; exit }' <<<"$VERIFY_STATUS")"
SIGNER_FINGERPRINT="$(
    printf '%s' "$SIGNER_FINGERPRINT" |
        tr -d '[:space:]' |
        tr '[:lower:]' '[:upper:]'
)"
if [[ "$SIGNER_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]]; then
    echo "signature key mismatch for $ARTIFACT" >&2
    exit 1
fi

echo "verified $ARTIFACT"
