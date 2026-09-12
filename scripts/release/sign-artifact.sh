#!/usr/bin/env bash
# Sign the exact final artifact bytes with the maintainer's release key.
set -euo pipefail
[[ $# == 1 && -f "$1" ]] || { echo "usage: $0 <artifact>" >&2; exit 2; }
: "${ROOST_RELEASE_FINGERPRINT:?set the release signing key fingerprint}"
cd "$(dirname "$1")"
ARTIFACT="$(basename "$1")"
shasum -a 256 "$ARTIFACT" > "$ARTIFACT.sha256"
gpg --armor --detach-sign --yes --local-user "$ROOST_RELEASE_FINGERPRINT" \
    --output "$ARTIFACT.asc" "$ARTIFACT"
