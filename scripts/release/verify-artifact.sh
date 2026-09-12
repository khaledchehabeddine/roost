#!/usr/bin/env bash
# Verify a final artifact against a separately trusted release fingerprint.
set -euo pipefail
[[ $# == 5 ]] || { echo "usage: $0 <artifact> <signature> <checksum> <public-key> <pinned-sha256>" >&2; exit 2; }
: "${ROOST_RELEASE_FINGERPRINT:?set the trusted release key fingerprint}"
FINGERPRINT="$(printf '%s' "$ROOST_RELEASE_FINGERPRINT" | tr '[:lower:]' '[:upper:]')"
[[ "$FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] || { echo "invalid fingerprint" >&2; exit 2; }
[[ "$5" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid pinned SHA-256" >&2; exit 2; }
for file in "${@:1:4}"; do [[ -f "$file" ]] || { echo "missing file: $file" >&2; exit 2; }; done
ACTUAL="$(shasum -a 256 "$1" | awk '{print $1}')"
[[ "$ACTUAL" == "$5" ]] || { echo "pinned SHA-256 mismatch" >&2; exit 1; }
# Match both the bytes and the named artifact; reject extra checksum entries.
awk -v hash="$ACTUAL" -v name="$(basename "$1")" \
    'NR == 1 { valid = NF == 2 && $1 == hash && $2 == name } END { exit !(NR == 1 && valid) }' "$3"
KEYRING="$(mktemp -d)"
trap 'rm -rf "$KEYRING"' EXIT
chmod 700 "$KEYRING"
gpg --homedir "$KEYRING" --batch --import "$4" >/dev/null 2>&1
STATUS="$(gpg --homedir "$KEYRING" --batch --status-fd 1 --verify "$2" "$1" 2>/dev/null)"
# VALIDSIG reports the signing subkey first and, when present, its primary key last.
awk -v fingerprint="$FINGERPRINT" \
    '$2 == "VALIDSIG" && ($3 == fingerprint || $NF == fingerprint) { valid = 1 } END { exit !valid }' <<< "$STATUS"
printf 'verified %s\n' "$1"
