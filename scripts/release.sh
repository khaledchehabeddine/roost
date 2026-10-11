#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

version=$1
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version. Use X.Y.Z." >&2
    exit 1
fi

git switch main
git pull --ff-only
cargo set-version --workspace "$version"
git commit -m "chore: Release v$version" Cargo.toml Cargo.lock
git tag "v$version"
git push --atomic origin main "v$version"
