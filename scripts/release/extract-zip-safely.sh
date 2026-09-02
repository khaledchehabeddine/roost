#!/usr/bin/env bash
#
# Validate a release ZIP before extracting it into a new directory.

set -euo pipefail

ARCHIVE="${1:-}"
DESTINATION="${2:-}"
MAX_ENTRIES=50000
MAX_UNCOMPRESSED_BYTES=2147483648
MAX_MEMBER_NAME_BYTES=1024

usage() {
    echo "usage: $0 <archive.zip> <new-destination>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

if [[ ! -f "$ARCHIVE" || -L "$ARCHIVE" ]]; then
    echo "ZIP archive must be a regular file: $ARCHIVE" >&2
    exit 2
fi

case "$DESTINATION" in
    "" | / | . | .. | */. | */..)
        echo "unsafe ZIP extraction destination: $DESTINATION" >&2
        exit 2
        ;;
esac

if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
    echo "ZIP extraction destination already exists: $DESTINATION" >&2
    exit 2
fi

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

require_tool awk
require_tool grep
require_tool sort
require_tool tr
require_tool unzip
require_tool uniq
require_tool wc
require_tool zipinfo

TMP="$(mktemp -d)"
cleanup() {
    rm -rf "${TMP:?}"
}
trap cleanup EXIT

MEMBERS="$TMP/members"
NORMALIZED_MEMBERS="$TMP/normalized-members"
CASE_FOLDED_MEMBERS="$TMP/case-folded-members"
MODES="$TMP/modes"

if ! LC_ALL=C zipinfo -1 "$ARCHIVE" > "$MEMBERS"; then
    echo "could not list ZIP members: $ARCHIVE" >&2
    exit 1
fi

SUMMARY="$(LC_ALL=C zipinfo -t "$ARCHIVE")"
ENTRY_COUNT="$(printf '%s\n' "$SUMMARY" | awk 'NR == 1 { print $1 }')"
UNCOMPRESSED_BYTES="$(printf '%s\n' "$SUMMARY" | awk 'NR == 1 { print $3 }')"

if [[ ! "$ENTRY_COUNT" =~ ^[0-9]+$ || ! "$UNCOMPRESSED_BYTES" =~ ^[0-9]+$ ]]; then
    echo "could not read ZIP entry totals: $ARCHIVE" >&2
    exit 1
fi
if [[ "$ENTRY_COUNT" -eq 0 || "$ENTRY_COUNT" -gt "$MAX_ENTRIES" ]]; then
    echo "ZIP entry count is outside the allowed range: $ENTRY_COUNT" >&2
    exit 1
fi
if [[ "$UNCOMPRESSED_BYTES" -gt "$MAX_UNCOMPRESSED_BYTES" ]]; then
    echo "ZIP expands beyond $MAX_UNCOMPRESSED_BYTES bytes: $UNCOMPRESSED_BYTES" >&2
    exit 1
fi

LISTED_COUNT="$(wc -l < "$MEMBERS" | tr -d '[:space:]')"
if [[ "$LISTED_COUNT" -ne "$ENTRY_COUNT" ]]; then
    echo "ZIP member list is ambiguous: expected $ENTRY_COUNT lines, found $LISTED_COUNT" >&2
    exit 1
fi

while IFS= read -r member; do
    if [[ -z "$member" || "${#member}" -gt "$MAX_MEMBER_NAME_BYTES" ]]; then
        echo "ZIP contains an empty or overlong member name" >&2
        exit 1
    fi
    if [[ ! "$member" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        echo "ZIP member name is not portable: $member" >&2
        exit 1
    fi
    if [[ "$member" == /* || "$member" == *//* || "$member" =~ ^[A-Za-z]: ]]; then
        echo "ZIP member path is unsafe: $member" >&2
        exit 1
    fi

    normalized="${member%/}"
    if [[ -z "$normalized" ]]; then
        echo "ZIP member path is unsafe: $member" >&2
        exit 1
    fi

    IFS='/' read -r -a components <<< "$normalized"
    for component in "${components[@]}"; do
        if [[ -z "$component" || "$component" == . || "$component" == .. ]]; then
            echo "ZIP member path is unsafe: $member" >&2
            exit 1
        fi
    done

    printf '%s\n' "$normalized"
done < "$MEMBERS" > "$NORMALIZED_MEMBERS"

if LC_ALL=C sort "$NORMALIZED_MEMBERS" | uniq -d | grep -q .; then
    echo "ZIP contains duplicate normalized member paths" >&2
    exit 1
fi

tr '[:upper:]' '[:lower:]' < "$NORMALIZED_MEMBERS" > "$CASE_FOLDED_MEMBERS"
if LC_ALL=C sort "$CASE_FOLDED_MEMBERS" | uniq -d | grep -q .; then
    echo "ZIP contains case-colliding member paths" >&2
    exit 1
fi

LC_ALL=C zipinfo -l "$ARCHIVE" |
    awk 'NR > 2 && $1 ~ /^[-dlcbps]/ { print substr($1, 1, 1) }' > "$MODES"
MODE_COUNT="$(wc -l < "$MODES" | tr -d '[:space:]')"
if [[ "$MODE_COUNT" -ne "$ENTRY_COUNT" ]]; then
    echo "ZIP contains unsupported member metadata" >&2
    exit 1
fi
if grep -Ev '^[-d]$' "$MODES" | grep -q .; then
    echo "ZIP contains a link or special file" >&2
    exit 1
fi

mkdir -m 700 "$DESTINATION"
if ! unzip -q "$ARCHIVE" -d "$DESTINATION"; then
    rm -rf "${DESTINATION:?}"
    echo "could not extract ZIP archive: $ARCHIVE" >&2
    exit 1
fi

if find "$DESTINATION" ! -type f ! -type d -print -quit | grep -q .; then
    rm -rf "${DESTINATION:?}"
    echo "ZIP extraction produced a link or special file" >&2
    exit 1
fi
