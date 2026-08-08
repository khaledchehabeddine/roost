#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [[ "$#" -ne 0 ]]; then
    echo "usage: scripts/push-reviewed-branch.sh" >&2
    exit 2
fi

cd "$ROOT"
exec git \
    -c remote.origin.mirror=false \
    -c push.gpgSign=false \
    -c push.pushOption= \
    push --no-follow-tags -u origin HEAD
