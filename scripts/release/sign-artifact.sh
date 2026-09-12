#!/usr/bin/env bash
# Sign the exact final artifact bytes with the maintainer's release key.
set -euo pipefail
[[ $# == 1 && -f "$1" ]] || { echo "usage: $0 <artifact>" >&2; exit 2; }
: "${ROOST_RELEASE_FINGERPRINT:?set the release signing key fingerprint}"
[[ "$ROOST_RELEASE_FINGERPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || { echo "invalid fingerprint" >&2; exit 2; }
cd "$(dirname "$1")"
ARTIFACT="$(basename "$1")"
shasum -a 256 "$ARTIFACT" > "$ARTIFACT.sha256"
ARGS=(--armor --detach-sign --yes --local-user "$ROOST_RELEASE_FINGERPRINT")
if [[ "${ROOST_RELEASE_PASSPHRASE+x}" == x ]]; then
    gpg "${ARGS[@]}" --batch --pinentry-mode loopback --passphrase-fd 3 \
        --output "$ARTIFACT.asc" "$ARTIFACT" 3<<< "$ROOST_RELEASE_PASSPHRASE"
else
    gpg "${ARGS[@]}" --output "$ARTIFACT.asc" "$ARTIFACT"
fi
